import Charts
import SwiftUI
import TVTimeRecoveryCore

private struct PresentedError: Identifiable {
  let id = UUID()
  let message: String
}

private struct RecoveryChartMetric: Identifiable {
  let label: String
  let value: Int

  var id: String { label }
}

@MainActor
struct BackupStepView: View {
  let chooseBackup: () async throws -> URL?
  let onSelected: (URL) throws -> Void
  let onShowRecoveries: () throws -> Void
  @State private var presentedError: PresentedError?

  var body: some View {
    VStack(spacing: 22) {
      Image(systemName: "externaldrive")
        .font(.system(size: 48))
        .foregroundStyle(.tint)
        .accessibilityHidden(true)
      Text("Choose your encrypted local backup")
        .font(.title2.weight(.semibold))
        .phaseHeading()
      Text(
        "Select the completed Finder, Apple Devices, or iTunes backup. "
          + "The app reads the backup without intentionally changing it."
      )
      .foregroundStyle(.secondary)
      .multilineTextAlignment(.center)
      .frame(maxWidth: 520)
      Text(
        "The picker normally opens at Apple’s Backup folder. If one backup is present, simply "
          + "choose that folder. If several appear, open the backup you want first."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
      .multilineTextAlignment(.center)
      .frame(maxWidth: 520)
      Button("Choose Backup…") {
        Task {
          do {
            if let selected = try await chooseBackup() {
              try onSelected(selected)
            }
          } catch {
            presentedError = PresentedError(message: safeMessage(for: error))
          }
        }
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .keyboardShortcut(.defaultAction)
      Button("Show Previous Recoveries") {
        do {
          try onShowRecoveries()
        } catch {
          presentedError = PresentedError(message: safeMessage(for: error))
        }
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .alert(item: $presentedError) { error in
      Alert(title: Text("Recovery could not start"), message: Text(error.message))
    }
  }
}

@MainActor
struct ConfirmationStepView: View {
  let summary: PreflightSummary
  let destinationIdentity: String
  let outputFolderName: String
  let onStart: (String, Bool) -> Void
  let onBack: () -> Void
  @State private var password = ""
  @State private var acknowledgesSensitiveOutput = false

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        Text("Ready for private recovery")
          .font(.title2.weight(.semibold))
          .phaseHeading()
        Text("The encrypted backup passed read-only preflight checks.")
          .foregroundStyle(.secondary)

        Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 9) {
          summaryRow("Encrypted backup", summary.encrypted ? "Confirmed" : "Not confirmed")
          summaryRow("Snapshot state", displayMetadata(summary.snapshotState))
          summaryRow("Backup date", displayMetadata(summary.backupDate))
          summaryRow("Destination", destinationIdentity)
          summaryRow("Destination protection", "Private app-managed local storage")
          summaryRow("Output folder", outputFolderName)
          summaryRow("Backup files", summary.backupRegularFiles.formatted())
          summaryRow("Total backup size", byteCount(summary.backupLogicalBytes))
          summaryRow("Manifest database", byteCount(summary.manifestDatabaseBytes))
          summaryRow("Destination free", byteCount(summary.destinationFreeBytes))
          summaryRow("Initial preflight space floor", byteCount(summary.minimumWorkingBytes))
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

        Text(
          "Before extraction, recovery checks space again for the selected TV Time data, "
            + "the largest encrypted payload's temporary staging copy, safety headroom, and "
            + "a retained decrypted manifest only when that option is enabled."
        )
        .font(.callout)
        .foregroundStyle(.secondary)

        VStack(alignment: .leading, spacing: 6) {
          Label("Acknowledge plaintext exposure", systemImage: "lock.shield")
            .font(.headline)
          Text(
            "Recovered reports are readable plaintext stored in this app’s private local data "
              + "folder. Anyone with access to this Mac account may be able to read them."
          )
          .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)

        if !summary.warnings.isEmpty {
          VStack(alignment: .leading, spacing: 6) {
            Label("Preflight note", systemImage: "exclamationmark.triangle")
              .font(.headline)
            ForEach(summary.warnings, id: \.self) { warning in
              Text(warning)
                .foregroundStyle(.secondary)
            }
          }
        }

        SecureField("Encrypted backup password", text: $password)
          .textFieldStyle(.roundedBorder)
          .onSubmit(start)
        Text(
          "The password stays on this Mac, is sent only to the bundled helper, and is not saved."
        )
        .font(.callout)
        .foregroundStyle(.secondary)

        Toggle(isOn: $acknowledgesSensitiveOutput) {
          Text(
            "I understand the recovered files contain sensitive viewing history and are "
              + "readable plaintext on this Mac."
          )
        }

        HStack {
          Button("Choose Different Backup", action: onBack)
            .keyboardShortcut(.cancelAction)
          Spacer()
          Button("Start Recovery", action: start)
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || !acknowledgesSensitiveOutput)
            .keyboardShortcut(.defaultAction)
        }
      }
      .frame(maxWidth: 620)
      .frame(maxWidth: .infinity)
      .padding(.vertical, 1)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .onDisappear {
      password.removeAll(keepingCapacity: false)
    }
  }

  @ViewBuilder
  private func summaryRow(_ label: String, _ value: String) -> some View {
    GridRow {
      Text(label)
        .foregroundStyle(.secondary)
      Text(value)
        .fontWeight(.medium)
        .textSelection(.enabled)
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel(label)
    .accessibilityValue(value)
  }

  private func displayMetadata(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? "Unavailable" : trimmed
  }

  private func start() {
    guard !password.isEmpty, acknowledgesSensitiveOutput else {
      return
    }
    let suppliedPassword = password
    password.removeAll(keepingCapacity: false)
    onStart(suppliedPassword, acknowledgesSensitiveOutput)
  }
}

@MainActor
struct RecoveryProgressView: View {
  let title: String
  let progress: RecoveryProgress
  let cancelTitle: String
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 20) {
      Text(title)
        .font(.title2.weight(.semibold))
        .phaseHeading()
      if let fraction = progress.fractionCompleted {
        ProgressView(value: fraction)
          .frame(maxWidth: 460)
          .accessibilityLabel(title)
          .accessibilityValue(accessibilityProgressValue)
      } else {
        ProgressView()
          .controlSize(.large)
          .accessibilityLabel(title)
          .accessibilityValue(accessibilityProgressValue)
      }
      Text(progress.message)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .frame(maxWidth: 520)
      if let current = progress.current, let total = progress.total, total > 0 {
        Text("\(current.formatted()) of \(total.formatted())")
          .font(.callout.monospacedDigit())
          .foregroundStyle(.secondary)
      }
      Button(cancelTitle, role: .cancel, action: onCancel)
        .keyboardShortcut(.cancelAction)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var accessibilityProgressValue: String {
    if let current = progress.current, let total = progress.total, total > 0 {
      return "\(current.formatted()) of \(total.formatted())"
    }
    return progress.message
  }
}

@MainActor
struct CancellingView: View {
  var body: some View {
    VStack(spacing: 18) {
      ProgressView()
        .controlSize(.large)
        .accessibilityLabel("Cancellation in progress")
        .accessibilityValue("Stopping the current operation safely")
      Text("Stopping safely…")
        .font(.title3.weight(.semibold))
        .phaseHeading()
      Text("Current output will not be deleted or reused.")
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

@MainActor
struct RecoveryResultView: View {
  let summary: RecoverySummary
  let hasVisualReport: Bool
  let hasPDFReport: Bool
  let onOpenVisualReport: () throws -> Void
  let onOpenPDFReport: () throws -> Void
  let onOpenMarkdown: () throws -> Void
  let onReveal: () throws -> Void
  let onStartAgain: () -> Void
  @State private var presentedError: PresentedError?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        Label("Recovery completed", systemImage: "checkmark.circle.fill")
          .font(.title2.weight(.semibold))
          .foregroundStyle(.green)
          .phaseHeading()
        Text("The private reports preserve every recovered record and each available title/name.")
          .foregroundStyle(.secondary)

        VStack(alignment: .leading, spacing: 12) {
          Label("Recovery package verified", systemImage: "checkmark.shield.fill")
            .font(.headline)
            .foregroundStyle(.green)
          Text(
            "This screen appears only after the app reopens the completed package from disk "
              + "and validates it. Keep the original encrypted backup until you have reviewed "
              + "the recovered titles."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 9) {
            verificationRow("Selected backup data", "Unchanged during extraction")
            verificationRow("Completion markers", "Complete and consistent")
            verificationRow("Copied files", "Sizes and hashes match the inventory")
            verificationRow("Report package", "Sealed artifacts match the completion record")
          }
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

        if hasRecoveredRecords {
          VStack(alignment: .leading, spacing: 12) {
            Label("Recovered data overview", systemImage: "chart.bar.xaxis")
              .font(.headline)
            Text(
              "This chart contains aggregate counts only. Open a private report to "
                + "view recovered names and titles."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            Text(
              "Series counts are recovered cache records, not necessarily distinct named "
                + "titles. The private reports provide the canonical and named-title views."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            Chart(chartMetrics) { metric in
              BarMark(
                x: .value("Recovered count", metric.value),
                y: .value("Category", metric.label)
              )
              .foregroundStyle(Color.accentColor.gradient)
              .cornerRadius(4)
              .annotation(position: .trailing, alignment: .leading) {
                Text(metric.value.formatted())
                  .font(.caption.monospacedDigit())
                  .foregroundStyle(.secondary)
                  .accessibilityHidden(true)
              }
            }
            .chartXScale(domain: 0...chartUpperBound)
            .chartXAxis {
              AxisMarks(position: .bottom, values: .automatic(desiredCount: 5)) {
                AxisGridLine()
                AxisTick()
                AxisValueLabel()
              }
            }
            .frame(height: 260)
            .accessibilityHidden(true)
          }
          .padding(16)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        } else {
          VStack(alignment: .leading, spacing: 8) {
            Label("No supported TV Time records were found", systemImage: "text.magnifyingglass")
              .font(.headline)
            Text(
              "The selected TV Time files were copied successfully, but this backup "
                + "did not contain supported library, favorite, episode, or watch-event "
                + "records. Open the reports to review the recovered tables and diagnostics."
            )
            .foregroundStyle(.secondary)
          }
          .accessibilityElement(children: .combine)
          .padding(16)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        }

        Grid(alignment: .leading, horizontalSpacing: 28, verticalSpacing: 10) {
          resultRow("Recovered series records", summary.analysis.seriesLibrary)
          resultRow("Movie records total", summary.analysis.movieCount)
          resultRow("Watched movies", summary.analysis.watchedMovies)
          resultRow("Saved movies", summary.analysis.movieWatchlist)
          resultRow("Favorite shows", summary.analysis.favoriteShows)
          resultRow("Favorite movies", summary.analysis.favoriteMovies)
          resultRow("Watch events", summary.analysis.watchEvents)
          resultRow(
            "Watch events matched to titles",
            summary.analysis.watchEventsWithTitles,
            suffix: " of \(summary.analysis.watchEvents.formatted())"
          )
          resultRow(
            "Watch events without cached titles",
            summary.analysis.watchEventsWithoutTitles,
            suffix: " of \(summary.analysis.watchEvents.formatted())"
          )
          resultRow("Cached episodes", summary.analysis.episodeCacheUnique)
          resultRow(
            "Files copied",
            summary.extraction.filesExtracted,
            suffix: " of \(summary.extraction.filesExpected.formatted())"
          )
          resultRow("Byte-count differences", summary.extraction.sizeDiscrepancyCount)
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

        VStack(alignment: .leading, spacing: 10) {
          Label("Recovered media references", systemImage: "photo.on.rectangle.angled")
            .font(.headline)
          Grid(alignment: .leading, horizontalSpacing: 28, verticalSpacing: 10) {
            resultRow("Image references", summary.report.imageCacheReferences)
            resultRow("Trailer references", summary.report.trailerReferences)
            resultRow("Media URLs", summary.report.mediaURLs)
          }
          Text(
            "These are private aggregate counts. Open a report to inspect the sanitized "
              + "reference tables."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

        if summary.extraction.sizeDiscrepancyCount > 0 {
          VStack(alignment: .leading, spacing: 7) {
            Label(
              "\(summary.extraction.sizeDiscrepancyCount.formatted()) byte-count "
                + "differences recorded",
              systemImage: "exclamationmark.triangle"
            )
            .font(.headline)
            Text(
              "All expected selected files were copied. These differences are kept as "
                + "explicit salvage notes; review the Copy-size differences section in a "
                + "private report."
            )
            .foregroundStyle(.secondary)
          }
          .accessibilityElement(children: .combine)
          .padding(16)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        }

        reportAvailability

        VStack(alignment: .leading, spacing: 10) {
          ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
              documentActionButtons
            }
            VStack(alignment: .leading, spacing: 8) {
              documentActionButtons
            }
          }
          ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
              Button("Show Recovery Folder") {
                perform(onReveal)
              }
              Button("Start Again", action: onStartAgain)
            }
            VStack(alignment: .leading, spacing: 8) {
              Button("Show Recovery Folder") {
                perform(onReveal)
              }
              Button("Start Again", action: onStartAgain)
            }
          }
        }
      }
      .frame(maxWidth: 640)
      .frame(maxWidth: .infinity)
      .padding(.vertical, 1)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .alert(item: $presentedError) { error in
      Alert(title: Text("Output unavailable"), message: Text(error.message))
    }
  }

  private var chartMetrics: [RecoveryChartMetric] {
    [
      RecoveryChartMetric(label: "Series records", value: summary.analysis.seriesLibrary),
      RecoveryChartMetric(label: "Watched movies", value: summary.analysis.watchedMovies),
      RecoveryChartMetric(label: "Saved movies", value: summary.analysis.movieWatchlist),
      RecoveryChartMetric(label: "Favorite shows", value: summary.analysis.favoriteShows),
      RecoveryChartMetric(label: "Favorite movies", value: summary.analysis.favoriteMovies),
      RecoveryChartMetric(label: "Watch events", value: summary.analysis.watchEvents),
      RecoveryChartMetric(label: "Cached episodes", value: summary.analysis.episodeCacheUnique),
    ]
  }

  private var hasRecoveredRecords: Bool {
    summary.analysis.hasRecoveredRecords
  }

  private var chartUpperBound: Int {
    let maximum = max(0, chartMetrics.map(\.value).max() ?? 0)
    guard maximum > 0 else {
      return 1
    }
    let padding = max(1, maximum / 7)
    let (upperBound, overflow) = maximum.addingReportingOverflow(padding)
    return overflow ? Int.max : upperBound
  }

  private var reportAvailability: some View {
    VStack(alignment: .leading, spacing: 10) {
      Label("Private recovery package", systemImage: "doc.text.magnifyingglass")
        .font(.headline)
      Text("Start with the visual report to browse recovered titles, charts, and tables offline.")
        .font(.callout)
        .foregroundStyle(.secondary)
      Grid(alignment: .leading, horizontalSpacing: 28, verticalSpacing: 8) {
        availabilityRow(
          "Visual report",
          detail: "Accessible offline HTML catalogue",
          available: hasVisualReport
        )
        availabilityRow(
          "Print-friendly PDF",
          detail: "Charts, contents, tables, and page numbers",
          available: hasPDFReport
        )
        availabilityRow(
          "Markdown report",
          detail: "Complete portable text catalogue",
          available: true
        )
      }
      if !hasPDFReport {
        Text(
          summary.report.displayPDFOmissionReason
            ?? "PDF was not created. The Visual and Markdown reports remain complete."
        )
        .font(.callout)
        .foregroundStyle(.secondary)
      }
      Text(
        "Reports open in your default browser or viewer. Their private filenames may "
          + "appear in that app's history or Recent Items."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
    }
    .padding(16)
    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
  }

  @ViewBuilder
  private var documentActionButtons: some View {
    if hasVisualReport {
      Button {
        perform(onOpenVisualReport)
      } label: {
        Label("Open Visual Report", systemImage: "chart.bar.doc.horizontal")
      }
      .buttonStyle(.borderedProminent)
      .keyboardShortcut(.defaultAction)
    }
    if hasPDFReport {
      Button {
        perform(onOpenPDFReport)
      } label: {
        Label("Open PDF", systemImage: "doc.richtext")
      }
    }
    if hasVisualReport {
      Button {
        perform(onOpenMarkdown)
      } label: {
        Label("Open Markdown", systemImage: "doc.plaintext")
      }
    } else {
      Button {
        perform(onOpenMarkdown)
      } label: {
        Label("Open Markdown", systemImage: "doc.plaintext")
      }
      .buttonStyle(.borderedProminent)
    }
  }

  @ViewBuilder
  private func resultRow(_ label: String, _ value: Int, suffix: String = "") -> some View {
    GridRow {
      Text(label)
        .foregroundStyle(.secondary)
      Text(value.formatted() + suffix)
        .fontWeight(.medium)
        .monospacedDigit()
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel(label)
    .accessibilityValue(value.formatted() + suffix)
  }

  @ViewBuilder
  private func availabilityRow(_ label: String, detail: String, available: Bool) -> some View {
    GridRow {
      VStack(alignment: .leading, spacing: 2) {
        Text(label)
          .fontWeight(.medium)
        Text(detail)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Label(available ? "Ready" : "Not created", systemImage: available ? "checkmark" : "minus")
        .fontWeight(.medium)
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel(label)
    .accessibilityValue(available ? "Ready" : "Not created")
  }

  @ViewBuilder
  private func verificationRow(_ label: String, _ value: String) -> some View {
    GridRow {
      Text(label)
        .foregroundStyle(.secondary)
      Label(value, systemImage: "checkmark.circle.fill")
        .fontWeight(.medium)
        .foregroundStyle(.primary)
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel(label)
    .accessibilityValue(value)
  }

  private func perform(_ action: () throws -> Void) {
    do {
      try action()
    } catch {
      presentedError = PresentedError(message: safeMessage(for: error))
    }
  }
}

@MainActor
struct RecoveryErrorView: View {
  let failure: RecoveryFailure
  let onPrimaryAction: () -> Void
  let onStartOver: () -> Void
  let canRevealOutput: Bool
  let onRevealOutput: () throws -> Void
  @State private var presentedError: PresentedError?

  private var recoveryPlan: RecoveryFailureRecoveryPlan {
    failure.recoveryPlan
  }

  var body: some View {
    ScrollView {
      VStack(spacing: 18) {
        Image(
          systemName: recoveryPlan.isCancellation
            ? "stop.circle" : "exclamationmark.triangle"
        )
        .font(.system(size: 44))
        .foregroundStyle(recoveryPlan.isCancellation ? Color.secondary : Color.orange)
        .accessibilityHidden(true)
        Text(recoveryPlan.title)
          .font(.title2.weight(.semibold))
          .phaseHeading()
        Text(recoveryPlan.guidance)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 540)
        if let message = failure.userVisibleMessage {
          GroupBox {
            Text(message)
              .frame(maxWidth: .infinity, alignment: .leading)
              .fixedSize(horizontal: false, vertical: true)
              .textSelection(.enabled)
          } label: {
            Label("What happened", systemImage: "info.circle")
          }
          .frame(maxWidth: 540)
        }
        Text("Error reference: \(failure.userVisibleReferenceCode)")
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
          .accessibilityLabel("Error reference")
          .accessibilityValue(failure.userVisibleReferenceCode)
        if canRevealOutput {
          Text(
            "Incomplete output is preserved. Reveal it before starting over if you need to "
              + "inspect or remove that run."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 540)
        }
        ViewThatFits(in: .horizontal) {
          HStack(spacing: 12) {
            errorActionButtons
          }
          VStack(spacing: 8) {
            errorActionButtons
          }
        }
      }
      .frame(maxWidth: 560)
      .frame(maxWidth: .infinity)
      .padding(.vertical, 1)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .alert(item: $presentedError) { error in
      Alert(title: Text("Output unavailable"), message: Text(error.message))
    }
  }

  @ViewBuilder
  private var errorActionButtons: some View {
    if canRevealOutput {
      Button("Show Incomplete Recovery Folder") {
        do {
          try onRevealOutput()
        } catch {
          presentedError = PresentedError(message: safeMessage(for: error))
        }
      }
    }
    if let primaryActionTitle = recoveryPlan.primaryActionTitle {
      Button(primaryActionTitle, action: onPrimaryAction)
        .buttonStyle(.borderedProminent)
        .keyboardShortcut(.defaultAction)
    }
    Button("Start Over", action: onStartOver)
  }
}

private func byteCount(_ value: Int64) -> String {
  ByteCountFormatter.string(fromByteCount: value, countStyle: .file)
}

private func safeMessage(for error: Error) -> String {
  PrivacySafeErrorText.message(for: error)
}

private struct PhaseHeadingModifier: ViewModifier {
  @AccessibilityFocusState private var focused: Bool

  func body(content: Content) -> some View {
    content
      .accessibilityAddTraits(.isHeader)
      .accessibilityFocused($focused)
      .onAppear {
        Task { @MainActor in
          focused = true
        }
      }
  }
}

extension View {
  fileprivate func phaseHeading() -> some View {
    modifier(PhaseHeadingModifier())
  }
}
