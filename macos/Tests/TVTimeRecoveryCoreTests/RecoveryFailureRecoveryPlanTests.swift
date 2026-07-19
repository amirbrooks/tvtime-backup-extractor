import Testing

@testable import TVTimeRecoveryCore

@Suite
struct RecoveryFailureRecoveryPlanTests {
  @Test
  func testEveryKnownFailureHasDeterministicTailoredPresentation() {
    let expectations = [
      PlanExpectation(
        code: "invalid_input",
        route: .startOverOnly,
        title: "Selections failed a safety check",
        action: nil,
        guidance:
          "Start over and choose regular local folders that do not overlap the backup, cloud sync, shared folders, or Git repositories."
      ),
      PlanExpectation(
        code: "backup_unencrypted",
        route: .chooseBackup,
        title: "Encrypted backup required",
        action: "Choose Another Backup",
        guidance: "Choose a completed local backup with encryption enabled, then check it again."
      ),
      PlanExpectation(
        code: "backup_unfinished",
        route: .chooseBackup,
        title: "Backup is not finished",
        action: "Review Backup",
        guidance:
          "Let the device backup finish in Finder, Apple Devices, or iTunes, then choose the completed backup."
      ),
      PlanExpectation(
        code: "app_data_missing",
        route: .chooseBackup,
        title: "TV Time data was not found",
        action: "Choose Another Backup",
        guidance:
          "Choose a backup from a device and date when TV Time was installed and its data was present."
      ),
      PlanExpectation(
        code: "source_changed",
        route: .chooseBackup,
        title: "Backup changed during recovery",
        action: "Review Backup",
        guidance:
          "Make sure the backup is complete and no backup or sync is running, then choose it again."
      ),
      PlanExpectation(
        code: "unsupported_schema",
        route: .chooseBackup,
        title: "This TV Time data is not supported",
        action: "Choose Another Backup",
        guidance:
          "Choose another completed backup. This app will not guess at an unsupported data layout."
      ),
      PlanExpectation(
        code: "insufficient_space",
        route: .startOverOnly,
        title: "More local space is needed",
        action: nil,
        guidance:
          "Free space on this Mac, then start over. Existing incomplete output is preserved."
      ),
      PlanExpectation(
        code: "output_exists",
        route: .startOverOnly,
        title: "A fresh output folder is required",
        action: nil,
        guidance:
          "Start over so the app can prepare a fresh private local recovery folder. Existing files will not be overwritten."
      ),
      PlanExpectation(
        code: "unsafe_path",
        route: .startOverOnly,
        title: "Private storage is not safe",
        action: nil,
        guidance:
          "Start over so the app can recheck its private local storage. No recovered plaintext was written to an unsafe path."
      ),
      PlanExpectation(
        code: "destination_unencrypted",
        route: .startOverOnly,
        title: "Private storage could not be verified",
        action: nil,
        guidance:
          "Start over so the app can prepare and verify a fresh private local recovery folder."
      ),
      PlanExpectation(
        code: "backup_password_rejected",
        route: .retryPasswordWithFreshOutput,
        title: "Backup password was not accepted",
        action: "Recheck and Enter Password",
        guidance:
          "A fresh output folder will be prepared and the backup checked again before you enter the encryption password."
      ),
      PlanExpectation(
        code: "preflight_cancelled",
        route: .retrySamePreflight,
        title: "Backup check cancelled",
        action: "Check Again",
        guidance:
          "The same backup and private storage will be checked again. No recovery output will be created or changed.",
        isCancellation: true
      ),
      PlanExpectation(
        code: "cancelled",
        route: .retryWithFreshOutput,
        title: "Recovery cancelled",
        action: "Recheck with Fresh Output",
        guidance:
          "Incomplete output is preserved. A fresh output folder will be used for a new read-only backup check.",
        isCancellation: true
      ),
      PlanExpectation(
        code: "partial_extraction",
        route: .retryWithFreshOutput,
        title: "Some selected files could not be recovered",
        action: "Recheck with Fresh Output",
        guidance:
          "Preserve the incomplete output. A fresh output folder and a new read-only backup check are required before another attempt."
      ),
      PlanExpectation(
        code: "recovery_failed",
        route: .retryWithFreshOutput,
        title: "Recovery stopped safely",
        action: "Recheck with Fresh Output",
        guidance:
          "Preserve the incomplete output. A fresh output folder and a new read-only backup check are required before another attempt."
      ),
      PlanExpectation(
        code: "local_helper_error",
        route: .retryWithFreshOutput,
        title: "Recovery stopped safely",
        action: "Recheck with Fresh Output",
        guidance:
          "Preserve the incomplete output. A fresh output folder and a new read-only backup check are required before another attempt."
      ),
      PlanExpectation(
        code: "output_validation_failed",
        route: .retryWithFreshOutput,
        title: "Recovered output could not be verified",
        action: "Recheck with Fresh Output",
        guidance:
          "Preserve this output for review. A fresh output folder and a new read-only backup check are required before another attempt."
      ),
    ]

    for expectation in expectations {
      let failure = RecoveryFailure(
        code: expectation.code,
        message: "Safe helper message",
        retryable: false
      )
      let plan = failure.recoveryPlan
      expectEqual(plan.route, expectation.route, expectation.code)
      expectEqual(plan.title, expectation.title, expectation.code)
      expectEqual(plan.primaryActionTitle, expectation.action, expectation.code)
      expectEqual(plan.guidance, expectation.guidance, expectation.code)
      expectEqual(plan.isCancellation, expectation.isCancellation, expectation.code)
      expectFalse(plan.guidance.contains("/"), expectation.code)
      expectFalse(plan.guidance.localizedCaseInsensitiveContains("file:"), expectation.code)
    }
  }

  @Test
  func testUnknownFailureOffersOnlyStartOverEvenWhenMarkedRetryable() {
    let failure = RecoveryFailure(
      code: "unknown_future_failure",
      message: "Safe helper message",
      retryable: true
    )
    let plan = failure.recoveryPlan

    expectEqual(plan.route, .startOverOnly)
    expectNil(plan.primaryActionTitle)
    expectEqual(plan.title, "Recovery stopped safely")
    expectTrue(plan.guidance.contains("Start over"))
  }

  @Test
  func testKnownFailureProvidesSafeUserVisibleDetailAndReferenceCode() {
    let failure = RecoveryFailure(
      code: "insufficient_space",
      message:
        "  The destination ran out of usable space. Preserve the incomplete output and try again.  ",
      retryable: true
    )

    expectEqual(
      failure.userVisibleMessage,
      "The destination ran out of usable space. Preserve the incomplete output and try again."
    )
    expectEqual(failure.userVisibleReferenceCode, "insufficient_space")
  }

  @Test
  func testUserVisibleDetailFailsClosedForUntrustedOrSensitiveContent() {
    let rejectedMessages = [
      "The output at /Users/example/private could not be checked.",
      "The output at C:\\Users\\example could not be checked.",
      "The password is example-sensitive-value.",
      "The token was example-sensitive-value.",
      "The destination file: private-output could not be checked.",
      "Contact private@example.invalid for details.",
      "The destination\ncontained an unexpected file.",
      "The destination \u{202E}contained an unexpected file.",
      String(repeating: "a", count: 501),
    ]

    for message in rejectedMessages {
      let failure = RecoveryFailure(
        code: "recovery_failed",
        message: message,
        retryable: true
      )
      expectNil(failure.userVisibleMessage, message)
    }

    let unknownFailure = RecoveryFailure(
      code: "future_failure",
      message: "This otherwise safe text is not part of the trusted failure contract.",
      retryable: true
    )
    expectNil(unknownFailure.userVisibleMessage)
  }

  @Test
  func testReferenceCodeAllowsOnlyBoundedLowercaseProtocolIdentifiers() {
    let safeUnknownFailure = RecoveryFailure(
      code: "future_failure_2",
      message: "Hidden for unknown failures.",
      retryable: true
    )
    expectEqual(safeUnknownFailure.userVisibleReferenceCode, "future_failure_2")

    let rejectedCodes = [
      "", "UPPERCASE", "path/failure", "failure-name", String(repeating: "a", count: 65),
    ]
    for code in rejectedCodes {
      let failure = RecoveryFailure(code: code, message: "Hidden", retryable: false)
      expectEqual(failure.userVisibleReferenceCode, "unrecognized_failure", code)
    }
  }
}

private struct PlanExpectation {
  let code: String
  let route: RecoveryRetryRoute
  let title: String
  let action: String?
  let guidance: String
  var isCancellation = false
}
