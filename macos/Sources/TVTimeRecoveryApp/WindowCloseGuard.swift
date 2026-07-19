import AppKit
import SwiftUI

@MainActor
struct WindowCloseGuard: NSViewRepresentable {
  let allowsClose: Bool
  let requestClose: (@escaping @MainActor (Bool) -> Void) -> Void

  func makeNSView(context: Context) -> WindowCloseGuardView {
    let view = WindowCloseGuardView()
    view.allowsClose = allowsClose
    view.requestClose = requestClose
    return view
  }

  func updateNSView(_ nsView: WindowCloseGuardView, context: Context) {
    nsView.requestClose = requestClose
    nsView.allowsClose = allowsClose
  }

  static func dismantleNSView(_ nsView: WindowCloseGuardView, coordinator: ()) {
    nsView.releaseGuardedWindow()
  }
}

@MainActor
final class WindowCloseGuardView: NSView {
  var allowsClose = true {
    didSet {
      delegateProxy.allowsClose = allowsClose
      closeWhenSafeIfNeeded()
    }
  }

  var requestClose: (@escaping @MainActor (Bool) -> Void) -> Void = { decision in
    decision(false)
  }

  private let delegateProxy = WindowCloseDelegateProxy()
  private weak var guardedWindow: NSWindow?
  private var closeRequestPending = false
  private var closeWhenSafe = false

  override init(frame frameRect: NSRect) {
    super.init(frame: frameRect)
    delegateProxy.owner = self
  }

  required init?(coder: NSCoder) {
    super.init(coder: coder)
    delegateProxy.owner = self
  }

  override func viewWillMove(toWindow newWindow: NSWindow?) {
    if guardedWindow !== newWindow {
      releaseGuardedWindow()
    }
    super.viewWillMove(toWindow: newWindow)
  }

  override func viewDidMoveToWindow() {
    super.viewDidMoveToWindow()
    guard let window, guardedWindow !== window else {
      return
    }
    guardedWindow = window
    delegateProxy.forwardingDelegate = window.delegate
    delegateProxy.allowsClose = allowsClose
    window.delegate = delegateProxy
  }

  func releaseGuardedWindow() {
    guard let guardedWindow else {
      return
    }
    if guardedWindow.delegate === delegateProxy {
      guardedWindow.delegate = delegateProxy.forwardingDelegate
    }
    delegateProxy.forwardingDelegate = nil
    self.guardedWindow = nil
    closeRequestPending = false
    closeWhenSafe = false
  }

  fileprivate func shouldClose(_ sender: NSWindow) -> Bool {
    guard !allowsClose else {
      return delegateProxy.forwardingDelegate?.windowShouldClose?(sender) ?? true
    }
    guard !closeRequestPending else {
      return false
    }
    closeRequestPending = true
    requestClose { [weak self] confirmed in
      guard let self else {
        return
      }
      closeRequestPending = false
      closeWhenSafe = confirmed
      closeWhenSafeIfNeeded()
    }
    return false
  }

  private func closeWhenSafeIfNeeded() {
    guard allowsClose, closeWhenSafe, let guardedWindow else {
      return
    }
    closeWhenSafe = false
    Task { @MainActor [weak self, weak guardedWindow] in
      guard let self, let guardedWindow, self.guardedWindow === guardedWindow else {
        return
      }
      guardedWindow.performClose(nil)
    }
  }
}

@MainActor
private final class WindowCloseDelegateProxy: NSObject, NSWindowDelegate {
  weak var owner: WindowCloseGuardView?
  nonisolated(unsafe) weak var forwardingDelegate: (any NSWindowDelegate)?
  var allowsClose = true

  func windowShouldClose(_ sender: NSWindow) -> Bool {
    owner?.shouldClose(sender)
      ?? (forwardingDelegate?.windowShouldClose?(sender) ?? allowsClose)
  }

  override func responds(to selector: Selector!) -> Bool {
    if selector == #selector(NSWindowDelegate.windowShouldClose(_:)) {
      return true
    }
    return super.responds(to: selector) || forwardingDelegate?.responds(to: selector) == true
  }

  override func forwardingTarget(for selector: Selector!) -> Any? {
    if forwardingDelegate?.responds(to: selector) == true {
      return forwardingDelegate
    }
    return super.forwardingTarget(for: selector)
  }
}
