import Darwin
import Foundation

@MainActor
public protocol RecoveryHelperClient: AnyObject {
  func events(
    for request: RecoveryRequest,
    secret: Data?
  ) throws -> AsyncThrowingStream<HelperEvent, Error>

  func cancel()
}

@MainActor
public final class HelperProcessClient: RecoveryHelperClient {
  private enum TerminalKind: Sendable {
    case completed
    case failed
    case cancelled
  }

  private struct ActiveRun {
    let processIdentifier: pid_t
    let controlFileDescriptor: Int32
    let continuation: AsyncThrowingStream<HelperEvent, Error>.Continuation
    var readerFinished = false
    var processFinished = false
    var readerError: HelperClientError?
    var terminalKind: TerminalKind?
    var terminalEvent: HelperEvent?
    var waitStatus: Int32?
    var cancellationRequested = false
    var processMonitor: Task<Void, Never>?
    var shutdownEscalation: Task<Void, Never>?
  }

  private struct SpawnedProcess: Sendable {
    let processIdentifier: pid_t
    let controlWrite: Int32
    let eventRead: Int32
    let errorRead: Int32
    let secretWrite: Int32?
  }

  struct PipePair {
    let read: Int32
    let write: Int32
  }

  struct ParentDescriptorSet {
    private(set) var descriptors: [Int32]

    init(_ descriptors: [Int32?]) {
      self.descriptors = descriptors.compactMap { $0 }
    }

    mutating func closeAll(
      using closeDescriptor: (Int32) -> Int32 = Darwin.close
    ) {
      let owned = descriptors
      descriptors.removeAll(keepingCapacity: false)
      for descriptor in owned {
        _ = closeDescriptor(descriptor)
      }
    }
  }

  private struct ReaderOutcome: Sendable {
    let error: HelperClientError?
    let terminalKind: TerminalKind?
    let terminalEvent: HelperEvent?
  }

  private static let expectedHelperBundleIdentifier =
    "com.amirbrooks.tvtime-backup-extractor.helper"

  private let appBundleURL: URL
  private let helperBundleURL: URL
  private let helperURL: URL
  private var activeRun: ActiveRun?

  public init(bundle: Bundle = .main) {
    let appBundleURL = bundle.bundleURL.standardizedFileURL
    let helperBundleURL =
      appBundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("TVTimeHelper.bundle", isDirectory: true)
    self.appBundleURL = appBundleURL
    self.helperBundleURL = helperBundleURL
    helperURL =
      helperBundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("MacOS", isDirectory: true)
      .appendingPathComponent("tvtime-helper", isDirectory: false)
  }

  public func events(
    for request: RecoveryRequest,
    secret: Data?
  ) throws -> AsyncThrowingStream<HelperEvent, Error> {
    guard activeRun == nil else {
      throw HelperClientError.helperBusy
    }
    try validateBundledHelper()

    switch request.action {
    case .recover:
      guard
        request.backupReceipt != nil,
        let secret,
        !secret.isEmpty,
        secret.count <= HelperProtocolV3.maximumSecretBytes,
        secret.count <= Int(UInt32.max)
      else {
        throw HelperClientError.invalidFrame
      }
    case .preflight:
      guard request.backupReceipt == nil, secret == nil else {
        throw HelperClientError.invalidFrame
      }
    }

    let requestFrame = try HelperFrameEncoder.frame(HelperRequestEnvelope(request: request))
    let destinationParentDescriptor = try Self.openBoundDestinationParent(for: request)
    defer { Darwin.close(destinationParentDescriptor) }
    let spawned = try spawnHelper(
      destinationParentDescriptor: destinationParentDescriptor,
      requiresSecret: request.action == .recover
    )
    let (stream, continuation) = AsyncThrowingStream<HelperEvent, Error>.makeStream(
      bufferingPolicy: .bufferingNewest(128)
    )
    let processIdentifier = spawned.processIdentifier
    continuation.onTermination = { [weak self] termination in
      guard case .cancelled = termination else {
        return
      }
      Task { @MainActor [weak self] in
        self?.cancelIfActive(processIdentifier)
      }
    }

    activeRun = ActiveRun(
      processIdentifier: processIdentifier,
      controlFileDescriptor: spawned.controlWrite,
      continuation: continuation
    )

    do {
      try Self.writeAll(requestFrame, to: spawned.controlWrite)
      if let secret {
        guard let secretWrite = spawned.secretWrite else {
          throw HelperClientError.communicationFailed
        }
        try Self.writeSecret(secret, to: secretWrite)
      }
      if let secretWrite = spawned.secretWrite {
        Darwin.close(secretWrite)
      }
    } catch {
      var descriptors = ParentDescriptorSet([
        spawned.secretWrite,
        spawned.eventRead,
        spawned.errorRead,
        spawned.controlWrite,
      ])
      descriptors.closeAll()
      activeRun = nil
      continuation.finish(throwing: HelperClientError.communicationFailed)
      Task.detached(priority: .utility) {
        Self.terminateAndReapAfterLaunchFailure(processIdentifier)
      }
      throw HelperClientError.communicationFailed
    }

    let requiredCapability = request.action.rawValue
    let terminalObserver: @Sendable (TerminalKind, HelperEvent) -> Void = {
      [weak self] terminalKind, terminalEvent in
      Task { @MainActor [weak self] in
        self?.terminalEventObserved(
          processIdentifier: processIdentifier,
          terminalKind: terminalKind,
          terminalEvent: terminalEvent
        )
      }
    }
    Task.detached(priority: .userInitiated) { [weak self] in
      let outcome = Self.readEvents(
        from: spawned.eventRead,
        requiredCapability: requiredCapability,
        continuation: continuation,
        terminalObserved: terminalObserver
      )
      await self?.eventReaderFinished(
        processIdentifier: processIdentifier,
        outcome: outcome
      )
    }
    Task.detached(priority: .utility) {
      Self.drainStandardError(from: spawned.errorRead)
    }
    startProcessMonitor(processIdentifier)

    return stream
  }

  public func cancel() {
    guard let processIdentifier = activeRun?.processIdentifier else {
      return
    }
    cancelIfActive(processIdentifier)
  }

  private func cancelIfActive(_ processIdentifier: pid_t) {
    guard
      let run = activeRun,
      run.processIdentifier == processIdentifier,
      !run.processFinished,
      !run.cancellationRequested
    else {
      return
    }
    if reconcileProcessExitIfNeeded(processIdentifier) {
      return
    }
    guard
      var currentRun = activeRun,
      currentRun.processIdentifier == processIdentifier,
      !currentRun.processFinished
    else {
      return
    }
    currentRun.cancellationRequested = true
    let controlFileDescriptor = currentRun.controlFileDescriptor
    activeRun = currentRun

    var wroteCancelFrame = false
    do {
      let cancelFrame = try HelperFrameEncoder.frame(HelperCancelEnvelope())
      try Self.writeAll(cancelFrame, to: controlFileDescriptor)
      wroteCancelFrame = true
    } catch {
      // The process may have exited between reconciliation and this write. Do not signal
      // here; reconcile again before the bounded escalation decides whether a signal is safe.
    }
    if reconcileProcessExitIfNeeded(processIdentifier) {
      return
    }
    startShutdownEscalation(
      processIdentifier,
      initialGrace: wroteCancelFrame ? .seconds(3) : .milliseconds(100)
    )
  }

  private func validateBundledHelper() throws {
    let bundleRoot = appBundleURL.standardizedFileURL
    let helperBundleCandidate = helperBundleURL.standardizedFileURL
    let candidate = helperURL.standardizedFileURL
    guard
      helperBundleCandidate.path.hasPrefix(bundleRoot.path + "/"),
      candidate.path.hasPrefix(helperBundleCandidate.path + "/"),
      Self.pathHasNoSymbolicLinks(candidate),
      let helperBundle = Bundle(url: helperBundleCandidate),
      helperBundle.bundleIdentifier == Self.expectedHelperBundleIdentifier,
      helperBundle.bundleURL.standardizedFileURL == helperBundleCandidate,
      helperBundle.executableURL?.standardizedFileURL == candidate
    else {
      throw HelperClientError.helperUnavailable
    }
    var isDirectory: ObjCBool = false
    guard
      FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
      !isDirectory.boolValue,
      FileManager.default.isExecutableFile(atPath: candidate.path)
    else {
      throw HelperClientError.helperUnavailable
    }
    let values = try? candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    guard values?.isRegularFile == true, values?.isSymbolicLink != true else {
      throw HelperClientError.helperUnavailable
    }
  }

  private func startProcessMonitor(_ processIdentifier: pid_t) {
    guard
      var run = activeRun,
      run.processIdentifier == processIdentifier,
      !run.processFinished,
      run.processMonitor == nil
    else {
      return
    }
    run.processMonitor = Task { [weak self] in
      while !Task.isCancelled {
        guard let self else {
          return
        }
        if self.reconcileProcessExitIfNeeded(processIdentifier) {
          return
        }
        try? await Task.sleep(for: .milliseconds(50))
      }
    }
    activeRun = run
  }

  private func startShutdownEscalation(
    _ processIdentifier: pid_t,
    initialGrace: Duration
  ) {
    guard
      var run = activeRun,
      run.processIdentifier == processIdentifier,
      !run.processFinished,
      run.shutdownEscalation == nil
    else {
      return
    }
    run.shutdownEscalation = Task { [weak self] in
      try? await Task.sleep(for: initialGrace)
      guard !Task.isCancelled else {
        return
      }
      self?.signalIfActive(SIGINT, processIdentifier: processIdentifier)
      try? await Task.sleep(for: .seconds(2))
      guard !Task.isCancelled else {
        return
      }
      self?.signalIfActive(SIGTERM, processIdentifier: processIdentifier)
      try? await Task.sleep(for: .seconds(2))
      guard !Task.isCancelled else {
        return
      }
      self?.signalIfActive(SIGKILL, processIdentifier: processIdentifier)
    }
    activeRun = run
  }

  private func signalIfActive(_ signal: Int32, processIdentifier: pid_t) {
    guard
      let run = activeRun,
      run.processIdentifier == processIdentifier,
      !run.processFinished
    else {
      return
    }
    if reconcileProcessExitIfNeeded(processIdentifier) {
      return
    }
    Darwin.kill(processIdentifier, signal)
  }

  @discardableResult
  private func reconcileProcessExitIfNeeded(_ processIdentifier: pid_t) -> Bool {
    guard
      let run = activeRun,
      run.processIdentifier == processIdentifier
    else {
      return true
    }
    if run.processFinished {
      return true
    }

    while true {
      var status: Int32 = 0
      let result = Darwin.waitpid(processIdentifier, &status, WNOHANG)
      if result == processIdentifier {
        processFinished(processIdentifier: processIdentifier, status: status)
        return true
      }
      if result == 0 {
        return false
      }
      if result == -1, errno == EINTR {
        continue
      }
      processFinished(processIdentifier: processIdentifier, status: -1)
      return true
    }
  }

  private func eventReaderFinished(processIdentifier: pid_t, outcome: ReaderOutcome) {
    guard var run = activeRun, run.processIdentifier == processIdentifier else {
      return
    }
    run.readerFinished = true
    run.readerError = outcome.error
    run.terminalKind = outcome.terminalKind
    run.terminalEvent = outcome.terminalEvent
    activeRun = run
    if reconcileProcessExitIfNeeded(processIdentifier) {
      finishRunIfReady()
      return
    }
    if outcome.error != nil {
      cancelIfActive(processIdentifier)
    } else {
      startShutdownEscalation(processIdentifier, initialGrace: .seconds(2))
    }
    finishRunIfReady()
  }

  private func terminalEventObserved(
    processIdentifier: pid_t,
    terminalKind: TerminalKind,
    terminalEvent: HelperEvent
  ) {
    guard
      var run = activeRun,
      run.processIdentifier == processIdentifier,
      run.terminalKind == nil
    else {
      return
    }
    run.terminalKind = terminalKind
    run.terminalEvent = terminalEvent
    activeRun = run
    if !reconcileProcessExitIfNeeded(processIdentifier) {
      startShutdownEscalation(processIdentifier, initialGrace: .seconds(2))
    }
  }

  private func processFinished(processIdentifier: pid_t, status: Int32) {
    guard var run = activeRun, run.processIdentifier == processIdentifier else {
      return
    }
    run.processFinished = true
    run.waitStatus = status
    run.processMonitor?.cancel()
    run.processMonitor = nil
    run.shutdownEscalation?.cancel()
    run.shutdownEscalation = nil
    activeRun = run
    finishRunIfReady()
  }

  private func finishRunIfReady() {
    guard
      let run = activeRun,
      run.readerFinished,
      run.processFinished
    else {
      return
    }
    run.processMonitor?.cancel()
    run.shutdownEscalation?.cancel()
    Darwin.close(run.controlFileDescriptor)
    activeRun = nil

    if let error = run.readerError {
      run.continuation.finish(throwing: error)
      return
    }
    guard
      let terminalKind = run.terminalKind,
      let terminalEvent = run.terminalEvent,
      let waitStatus = run.waitStatus,
      Self.processExitedNormally(waitStatus)
    else {
      run.continuation.finish(throwing: HelperClientError.helperExitedUnexpectedly)
      return
    }
    switch terminalKind {
    case .completed:
      if !Self.processExitedSuccessfully(waitStatus) {
        run.continuation.finish(throwing: HelperClientError.helperExitedUnexpectedly)
        return
      }
    case .failed, .cancelled:
      if Self.processExitedSuccessfully(waitStatus) {
        run.continuation.finish(throwing: HelperClientError.helperExitedUnexpectedly)
        return
      }
    }
    run.continuation.yield(terminalEvent)
    run.continuation.finish()
  }

  nonisolated private static func terminateAndReapAfterLaunchFailure(
    _ processIdentifier: pid_t
  ) {
    Darwin.kill(processIdentifier, SIGTERM)
    for _ in 0..<100 {
      var status: Int32 = 0
      let result = Darwin.waitpid(processIdentifier, &status, WNOHANG)
      if result == processIdentifier || (result == -1 && errno == ECHILD) {
        return
      }
      if result == -1, errno != EINTR {
        return
      }
      Darwin.usleep(10_000)
    }

    Darwin.kill(processIdentifier, SIGKILL)
    var status: Int32 = 0
    while Darwin.waitpid(processIdentifier, &status, 0) == -1, errno == EINTR {}
  }

  nonisolated private static func processExitedNormally(_ status: Int32) -> Bool {
    status >= 0 && (status & 0x7F) == 0
  }

  nonisolated private static func processExitedSuccessfully(_ status: Int32) -> Bool {
    processExitedNormally(status) && ((status >> 8) & 0xFF) == 0
  }

  private func spawnHelper(
    destinationParentDescriptor: Int32,
    requiresSecret: Bool
  ) throws -> SpawnedProcess {
    let control = try Self.makePipe()
    let events: PipePair
    let errors: PipePair
    let secret: PipePair?
    var allocatedPipes = [control]
    do {
      events = try Self.makePipe()
      allocatedPipes.append(events)
      errors = try Self.makePipe()
      allocatedPipes.append(errors)
      if requiresSecret {
        let allocatedSecret = try Self.makePipe()
        secret = allocatedSecret
        allocatedPipes.append(allocatedSecret)
      } else {
        secret = nil
      }
    } catch {
      Self.closePipes(allocatedPipes)
      throw error
    }

    var fileActions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&fileActions) == 0 else {
      Self.closePipes(allocatedPipes)
      throw HelperClientError.launchFailed
    }
    defer { posix_spawn_file_actions_destroy(&fileActions) }

    var mappings: [(Int32, Int32)] = [
      (control.read, STDIN_FILENO),
      (events.write, STDOUT_FILENO),
      (errors.write, STDERR_FILENO),
      (destinationParentDescriptor, HelperProtocolV3.destinationParentFileDescriptor),
    ]
    if let secret {
      mappings.append((secret.read, HelperProtocolV3.secretFileDescriptor))
    }
    for (source, destination) in mappings {
      guard posix_spawn_file_actions_adddup2(&fileActions, source, destination) == 0 else {
        Self.closePipes(allocatedPipes)
        throw HelperClientError.launchFailed
      }
    }
    if !requiresSecret {
      guard
        posix_spawn_file_actions_addclose(
          &fileActions,
          HelperProtocolV3.secretFileDescriptor
        ) == 0
      else {
        Self.closePipes(allocatedPipes)
        throw HelperClientError.launchFailed
      }
    }
    let pipeDescriptors = allocatedPipes.flatMap { [$0.read, $0.write] }
    for descriptor in pipeDescriptors + [destinationParentDescriptor]
    where descriptor > HelperProtocolV3.destinationParentFileDescriptor {
      guard posix_spawn_file_actions_addclose(&fileActions, descriptor) == 0 else {
        Self.closePipes(allocatedPipes)
        throw HelperClientError.launchFailed
      }
    }

    var attributes: posix_spawnattr_t?
    guard posix_spawnattr_init(&attributes) == 0 else {
      Self.closePipes(allocatedPipes)
      throw HelperClientError.launchFailed
    }
    defer { posix_spawnattr_destroy(&attributes) }
    let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)
    guard posix_spawnattr_setflags(&attributes, flags) == 0 else {
      Self.closePipes(allocatedPipes)
      throw HelperClientError.launchFailed
    }

    let executablePath = helperURL.path
    var arguments = [strdup(executablePath), nil]
    defer { free(arguments[0]) }
    var processIdentifier: pid_t = 0
    let result = executablePath.withCString { executable in
      arguments.withUnsafeMutableBufferPointer { argumentBuffer in
        posix_spawn(
          &processIdentifier,
          executable,
          &fileActions,
          &attributes,
          argumentBuffer.baseAddress,
          environ
        )
      }
    }

    guard result == 0 else {
      Self.closePipes(allocatedPipes)
      throw HelperClientError.launchFailed
    }

    Darwin.close(control.read)
    Darwin.close(events.write)
    Darwin.close(errors.write)
    if let secret {
      Darwin.close(secret.read)
    }
    _ = fcntl(control.write, F_SETNOSIGPIPE, 1)
    if let secret {
      _ = fcntl(secret.write, F_SETNOSIGPIPE, 1)
    }
    return SpawnedProcess(
      processIdentifier: processIdentifier,
      controlWrite: control.write,
      eventRead: events.read,
      errorRead: errors.read,
      secretWrite: secret?.write
    )
  }

  nonisolated static func makePipe() throws -> PipePair {
    var descriptors: [Int32] = [0, 0]
    guard Darwin.pipe(&descriptors) == 0 else {
      throw HelperClientError.launchFailed
    }
    guard
      setCloseOnExec(descriptors[0]),
      setCloseOnExec(descriptors[1])
    else {
      Darwin.close(descriptors[0])
      Darwin.close(descriptors[1])
      throw HelperClientError.launchFailed
    }
    return PipePair(read: descriptors[0], write: descriptors[1])
  }

  nonisolated private static func setCloseOnExec(_ descriptor: Int32) -> Bool {
    var flags: Int32
    repeat {
      flags = Darwin.fcntl(descriptor, F_GETFD)
    } while flags == -1 && errno == EINTR
    guard flags >= 0 else {
      return false
    }
    var result: Int32
    repeat {
      result = Darwin.fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC)
    } while result == -1 && errno == EINTR
    return result == 0
  }

  nonisolated private static func closePipe(_ pipe: PipePair) {
    Darwin.close(pipe.read)
    Darwin.close(pipe.write)
  }

  nonisolated private static func closePipes(_ pipes: [PipePair]) {
    for pipe in pipes {
      closePipe(pipe)
    }
  }

  nonisolated static func openBoundDestinationParent(for request: RecoveryRequest) throws -> Int32 {
    let output = request.outputDirectory.standardizedFileURL
    guard output.isFileURL, output.path != "/" else {
      throw HelperClientError.destinationChanged
    }
    let parent = output.deletingLastPathComponent().standardizedFileURL
    let opened = try openDirectoryWithoutFollowingLinks(parent)
    defer { Darwin.close(opened) }

    var metadata = stat()
    guard
      Darwin.fstat(opened, &metadata) == 0,
      metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
      metadata.st_dev >= 0,
      DestinationDirectoryIdentity(
        device: UInt64(metadata.st_dev),
        inode: UInt64(metadata.st_ino)
      ) == request.destinationParentIdentity
    else {
      throw HelperClientError.destinationChanged
    }

    let duplicated = Darwin.fcntl(
      opened,
      F_DUPFD_CLOEXEC,
      HelperProtocolV3.destinationParentFileDescriptor + 1
    )
    guard duplicated >= 0 else {
      throw HelperClientError.launchFailed
    }
    return duplicated
  }

  nonisolated static func openDirectoryWithoutFollowingLinks(
    _ url: URL,
    trustedAnchor explicitAnchor: URL? = nil,
    componentOpened: ((URL) -> Void)? = nil
  ) throws -> Int32 {
    guard url.isFileURL else {
      throw HelperClientError.destinationChanged
    }
    let destination = url.standardizedFileURL
    let anchor: URL
    if let explicitAnchor {
      anchor = explicitAnchor.standardizedFileURL
    } else if let containerHome = sandboxContainerHome(containing: destination) {
      anchor = containerHome
    } else {
      anchor = URL(fileURLWithPath: "/", isDirectory: true)
    }
    guard let components = relativePathComponents(of: destination, beneath: anchor) else {
      throw HelperClientError.destinationChanged
    }

    let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    var current = anchor.path.withCString { Darwin.open($0, flags) }
    guard current >= 0 else {
      throw HelperClientError.destinationChanged
    }
    var openedURL = anchor
    for component in components {
      guard !component.isEmpty, component != ".", component != ".." else {
        Darwin.close(current)
        throw HelperClientError.destinationChanged
      }
      let next = component.withCString { Darwin.openat(current, $0, flags) }
      guard next >= 0 else {
        Darwin.close(current)
        throw HelperClientError.destinationChanged
      }
      Darwin.close(current)
      current = next
      openedURL.appendPathComponent(component, isDirectory: true)
      componentOpened?(openedURL)
    }
    return current
  }

  nonisolated private static func sandboxContainerHome(containing destination: URL) -> URL? {
    let applicationSupport = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    )[0].standardizedFileURL
    let home =
      applicationSupport
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .standardizedFileURL
    guard
      home.path.contains("/Library/Containers/"),
      relativePathComponents(of: destination, beneath: home) != nil
    else {
      return nil
    }
    return home
  }

  nonisolated private static func relativePathComponents(
    of destination: URL,
    beneath anchor: URL
  ) -> [String]? {
    let destinationPath = destination.standardizedFileURL.path
    let anchorPath = anchor.standardizedFileURL.path
    if anchorPath == "/" {
      guard destinationPath.hasPrefix("/") else { return nil }
      var components = destination.standardizedFileURL.pathComponents
      if !components.isEmpty {
        components.removeFirst()
      }
      return components
    }
    guard destinationPath == anchorPath || destinationPath.hasPrefix(anchorPath + "/") else {
      return nil
    }
    guard destinationPath != anchorPath else { return [] }
    return destinationPath.dropFirst(anchorPath.count + 1).split(separator: "/").map(String.init)
  }

  nonisolated private static func pathHasNoSymbolicLinks(_ url: URL) -> Bool {
    guard url.isFileURL else { return false }
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    for component in url.standardizedFileURL.pathComponents.dropFirst() {
      current.appendPathComponent(component)
      var metadata = stat()
      let status = current.path.withCString { Darwin.lstat($0, &metadata) }
      guard status == 0, metadata.st_mode & mode_t(S_IFMT) != mode_t(S_IFLNK) else {
        return false
      }
    }
    return true
  }

  nonisolated private static func writeSecret(_ secret: Data, to descriptor: Int32) throws {
    guard
      !secret.isEmpty,
      secret.count <= HelperProtocolV3.maximumSecretBytes,
      secret.count <= Int(UInt32.max)
    else {
      throw HelperClientError.invalidFrame
    }

    var length = UInt32(secret.count).bigEndian
    try Swift.withUnsafeBytes(of: &length) { bytes in
      try writeAll(bytes, to: descriptor)
    }
    try secret.withUnsafeBytes { bytes in
      try writeAll(bytes, to: descriptor)
    }
  }

  nonisolated private static func writeAll(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { rawBuffer in
      try writeAll(rawBuffer, to: descriptor)
    }
  }

  nonisolated private static func writeAll(
    _ rawBuffer: UnsafeRawBufferPointer,
    to descriptor: Int32
  ) throws {
    guard let baseAddress = rawBuffer.baseAddress, !rawBuffer.isEmpty else {
      throw HelperClientError.communicationFailed
    }
    var offset = 0
    while offset < rawBuffer.count {
      let written = Darwin.write(
        descriptor,
        baseAddress.advanced(by: offset),
        rawBuffer.count - offset
      )
      if written > 0 {
        offset += written
      } else if written == -1, errno == EINTR {
        continue
      } else {
        throw HelperClientError.communicationFailed
      }
    }
  }

  nonisolated private static func readEvents(
    from descriptor: Int32,
    requiredCapability: String,
    continuation: AsyncThrowingStream<HelperEvent, Error>.Continuation,
    terminalObserved: @escaping @Sendable (TerminalKind, HelperEvent) -> Void
  ) -> ReaderOutcome {
    defer { Darwin.close(descriptor) }
    var bytes = [UInt8](repeating: 0, count: 16_384)
    var pending = Data()
    var expectedSequence = 1
    var terminalKind: TerminalKind?
    var terminalEvent: HelperEvent?
    var sawReady = false

    while true {
      let count = Darwin.read(descriptor, &bytes, bytes.count)
      if count > 0 {
        pending.append(bytes, count: count)
        while let newline = pending.firstIndex(of: 0x0A) {
          let line = Data(pending[..<newline])
          pending.removeSubrange(...newline)
          guard !line.isEmpty, line.count <= HelperProtocolV3.maximumFrameBytes else {
            return ReaderOutcome(
              error: .invalidEventStream,
              terminalKind: terminalKind,
              terminalEvent: terminalEvent
            )
          }
          let event: HelperEvent
          do {
            event = try HelperEventDecoder.decode(line)
          } catch {
            return ReaderOutcome(
              error: .invalidEventStream,
              terminalKind: terminalKind,
              terminalEvent: terminalEvent
            )
          }
          guard
            event.protocolVersion == HelperProtocolV3.version,
            event.sequence == expectedSequence,
            terminalKind == nil
          else {
            let error: HelperClientError =
              event.protocolVersion == HelperProtocolV3.version
              ? .invalidEventStream : .incompatibleProtocol
            return ReaderOutcome(
              error: error,
              terminalKind: terminalKind,
              terminalEvent: terminalEvent
            )
          }
          if expectedSequence == 1 {
            guard case .ready(let ready) = event.body,
              ready.minimumProtocolVersion <= HelperProtocolV3.version,
              ready.maximumProtocolVersion >= HelperProtocolV3.version,
              ready.capabilities.contains(requiredCapability),
              ready.capabilities.contains("cancel"),
              ready.capabilities.contains("destination-parent-fd"),
              ready.capabilities.contains("source-receipt-v1")
            else {
              return ReaderOutcome(
                error: .incompatibleProtocol,
                terminalKind: nil,
                terminalEvent: nil
              )
            }
            sawReady = true
          } else if case .ready = event.body {
            return ReaderOutcome(
              error: .invalidEventStream,
              terminalKind: terminalKind,
              terminalEvent: terminalEvent
            )
          }
          expectedSequence += 1
          if event.isTerminal {
            switch event.body {
            case .preflightCompleted where requiredCapability == RecoveryAction.preflight.rawValue:
              terminalKind = .completed
            case .recoveryCompleted where requiredCapability == RecoveryAction.recover.rawValue:
              terminalKind = .completed
            case .failed:
              terminalKind = .failed
            case .cancelled:
              terminalKind = .cancelled
            case .preflightCompleted, .recoveryCompleted, .ready, .progress:
              return ReaderOutcome(
                error: .invalidEventStream,
                terminalKind: terminalKind,
                terminalEvent: terminalEvent
              )
            }
            terminalEvent = event
            if let terminalKind {
              terminalObserved(terminalKind, event)
            }
          } else {
            continuation.yield(event)
          }
        }
        if pending.count > HelperProtocolV3.maximumFrameBytes {
          return ReaderOutcome(
            error: .invalidEventStream,
            terminalKind: terminalKind,
            terminalEvent: terminalEvent
          )
        }
      } else if count == 0 {
        break
      } else if errno == EINTR {
        continue
      } else {
        return ReaderOutcome(
          error: .communicationFailed,
          terminalKind: terminalKind,
          terminalEvent: terminalEvent
        )
      }
    }

    guard pending.isEmpty, sawReady, terminalKind != nil, terminalEvent != nil else {
      return ReaderOutcome(
        error: .helperExitedUnexpectedly,
        terminalKind: terminalKind,
        terminalEvent: terminalEvent
      )
    }
    return ReaderOutcome(
      error: nil,
      terminalKind: terminalKind,
      terminalEvent: terminalEvent
    )
  }

  nonisolated private static func drainStandardError(from descriptor: Int32) {
    defer { Darwin.close(descriptor) }
    var bytes = [UInt8](repeating: 0, count: 8_192)
    while true {
      let count = Darwin.read(descriptor, &bytes, bytes.count)
      if count > 0 {
        continue
      }
      if count == -1, errno == EINTR {
        continue
      }
      return
    }
  }

}
