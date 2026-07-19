import Foundation

public enum PrivacySafeErrorText {
  private static let fallback = "The operation could not be completed safely."

  public static func message(for error: Error) -> String {
    guard let localized = error as? LocalizedError else {
      return fallback
    }
    return screened(localized.errorDescription) ?? fallback
  }

  static func screened(_ value: String?) -> String? {
    guard let value else { return nil }
    let candidate = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard
      !candidate.isEmpty,
      candidate.count <= 500,
      !candidate.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
      !candidate.unicodeScalars.contains(where: isDirectionalControl),
      !candidate.contains("/"),
      !candidate.contains("\\"),
      !candidate.contains("~"),
      !candidate.contains("@")
    else {
      return nil
    }
    let lowercase = candidate.lowercased()
    let sensitiveMarkers = [
      "password", "passcode", "secret", "token", "api key", "api_key", "credential",
    ]
    guard
      !lowercase.localizedCaseInsensitiveContains("file:"),
      !sensitiveMarkers.contains(where: lowercase.contains)
    else {
      return nil
    }
    return candidate
  }

  private static func isDirectionalControl(_ scalar: Unicode.Scalar) -> Bool {
    switch scalar.value {
    case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
      true
    default:
      false
    }
  }
}
