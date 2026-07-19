import Foundation

enum StrictJSONValidationError: Error {
  case invalidJSON
}

/// Validates the security properties that Foundation's JSON decoders do not
/// preserve: duplicate object keys and bounded decoded structure complexity.
/// Callers still decode the same bytes into their typed contract afterwards.
enum StrictJSONValidator {
  static let maximumDepth = 128
  static let maximumNodes = 1_000_000
  static let maximumStringBytes = 8 * 1_024 * 1_024

  static func validate(_ data: Data, maximumBytes: Int64) throws {
    guard maximumBytes >= 0, Int64(data.count) <= maximumBytes else {
      throw StrictJSONValidationError.invalidJSON
    }
    try data.withUnsafeBytes { rawBuffer in
      var parser = Parser(bytes: rawBuffer.bindMemory(to: UInt8.self))
      try parser.validate()
    }
  }

  private struct Parser {
    let bytes: UnsafeBufferPointer<UInt8>
    var index = 0
    var nodeCount = 0

    mutating func validate() throws {
      guard !bytes.isEmpty else {
        throw StrictJSONValidationError.invalidJSON
      }
      try parseValue(depth: 0)
      try skipWhitespace()
      guard index == bytes.count else {
        throw StrictJSONValidationError.invalidJSON
      }
    }

    private mutating func parseValue(depth: Int) throws {
      try registerNode(depth: depth)
      try skipWhitespace()
      guard let byte = currentByte else {
        throw StrictJSONValidationError.invalidJSON
      }
      switch byte {
      case 0x7B:  // {
        try parseObject(depth: depth)
      case 0x5B:  // [
        try parseArray(depth: depth)
      case 0x22:  // "
        _ = try parseString(decode: false)
      case 0x74:  // true
        try consumeLiteral([0x74, 0x72, 0x75, 0x65])
      case 0x66:  // false
        try consumeLiteral([0x66, 0x61, 0x6C, 0x73, 0x65])
      case 0x6E:  // null
        try consumeLiteral([0x6E, 0x75, 0x6C, 0x6C])
      case 0x2D, 0x30...0x39:
        try parseNumber()
      default:
        throw StrictJSONValidationError.invalidJSON
      }
    }

    private mutating func parseObject(depth: Int) throws {
      index += 1
      try skipWhitespace()
      if consume(0x7D) {  // }
        return
      }

      var keys = Set<Data>()
      while true {
        try registerNode(depth: depth + 1)
        try skipWhitespace()
        guard currentByte == 0x22 else {
          throw StrictJSONValidationError.invalidJSON
        }
        let key = try parseString(decode: true)
        guard let key, keys.insert(key).inserted else {
          throw StrictJSONValidationError.invalidJSON
        }
        try skipWhitespace()
        guard consume(0x3A) else {  // :
          throw StrictJSONValidationError.invalidJSON
        }
        try parseValue(depth: depth + 1)
        try skipWhitespace()
        if consume(0x7D) {  // }
          return
        }
        guard consume(0x2C) else {  // ,
          throw StrictJSONValidationError.invalidJSON
        }
      }
    }

    private mutating func parseArray(depth: Int) throws {
      index += 1
      try skipWhitespace()
      if consume(0x5D) {  // ]
        return
      }
      while true {
        try parseValue(depth: depth + 1)
        try skipWhitespace()
        if consume(0x5D) {  // ]
          return
        }
        guard consume(0x2C) else {  // ,
          throw StrictJSONValidationError.invalidJSON
        }
      }
    }

    private mutating func parseString(decode: Bool) throws -> Data? {
      let tokenStart = index
      guard consume(0x22) else {  // "
        throw StrictJSONValidationError.invalidJSON
      }
      var decodedBytes = 0
      while let byte = currentByte {
        try checkCancellationPeriodically()
        switch byte {
        case 0x22:  // "
          index += 1
          guard decodedBytes <= StrictJSONValidator.maximumStringBytes else {
            throw StrictJSONValidationError.invalidJSON
          }
          guard decode else {
            return nil
          }
          guard let baseAddress = bytes.baseAddress else {
            throw StrictJSONValidationError.invalidJSON
          }
          let token = Data(
            bytes: baseAddress.advanced(by: tokenStart),
            count: index - tokenStart
          )
          let value = try JSONSerialization.jsonObject(with: token, options: .fragmentsAllowed)
          guard let string = value as? String else {
            throw StrictJSONValidationError.invalidJSON
          }
          // Python's duplicate-key hook compares decoded Unicode code-point
          // sequences without normalization. UTF-8 preserves that identity,
          // while Swift String equality intentionally applies canonical
          // equivalence and would reject a broader contract.
          return Data(string.utf8)
        case 0x00...0x1F:
          throw StrictJSONValidationError.invalidJSON
        case 0x5C:  // \
          index += 1
          guard let escape = currentByte else {
            throw StrictJSONValidationError.invalidJSON
          }
          switch escape {
          case 0x22, 0x2F, 0x5C, 0x62, 0x66, 0x6E, 0x72, 0x74:
            index += 1
            decodedBytes += 1
          case 0x75:  // u
            index += 1
            let first = try consumeHexCodeUnit()
            if (0xD800...0xDBFF).contains(first) {
              guard consume(0x5C), consume(0x75) else {
                throw StrictJSONValidationError.invalidJSON
              }
              let second = try consumeHexCodeUnit()
              guard (0xDC00...0xDFFF).contains(second) else {
                throw StrictJSONValidationError.invalidJSON
              }
              decodedBytes += 4
            } else if (0xDC00...0xDFFF).contains(first) {
              throw StrictJSONValidationError.invalidJSON
            } else if first <= 0x7F {
              decodedBytes += 1
            } else if first <= 0x7FF {
              decodedBytes += 2
            } else {
              decodedBytes += 3
            }
          default:
            throw StrictJSONValidationError.invalidJSON
          }
        default:
          index += 1
          decodedBytes += 1
        }
        guard decodedBytes <= StrictJSONValidator.maximumStringBytes else {
          throw StrictJSONValidationError.invalidJSON
        }
      }
      throw StrictJSONValidationError.invalidJSON
    }

    private mutating func consumeHexCodeUnit() throws -> UInt16 {
      var result: UInt16 = 0
      for _ in 0..<4 {
        guard let byte = currentByte, let digit = hexDigit(byte) else {
          throw StrictJSONValidationError.invalidJSON
        }
        result = (result << 4) | UInt16(digit)
        index += 1
      }
      return result
    }

    private func hexDigit(_ byte: UInt8) -> UInt8? {
      switch byte {
      case 0x30...0x39:
        byte - 0x30
      case 0x41...0x46:
        byte - 0x41 + 10
      case 0x61...0x66:
        byte - 0x61 + 10
      default:
        nil
      }
    }

    private mutating func parseNumber() throws {
      _ = consume(0x2D)  // -
      guard let first = currentByte else {
        throw StrictJSONValidationError.invalidJSON
      }
      if first == 0x30 {
        index += 1
      } else if (0x31...0x39).contains(first) {
        index += 1
        try consumeDigits()
      } else {
        throw StrictJSONValidationError.invalidJSON
      }

      if consume(0x2E) {  // .
        guard let byte = currentByte, (0x30...0x39).contains(byte) else {
          throw StrictJSONValidationError.invalidJSON
        }
        try consumeDigits()
      }
      if consume(0x65) || consume(0x45) {  // e or E
        _ = consume(0x2B) || consume(0x2D)  // + or -
        guard let byte = currentByte, (0x30...0x39).contains(byte) else {
          throw StrictJSONValidationError.invalidJSON
        }
        try consumeDigits()
      }
    }

    private mutating func consumeDigits() throws {
      while let byte = currentByte, (0x30...0x39).contains(byte) {
        index += 1
        try checkCancellationPeriodically()
      }
    }

    private mutating func consumeLiteral(_ literal: [UInt8]) throws {
      guard literal.count <= bytes.count - index else {
        throw StrictJSONValidationError.invalidJSON
      }
      for offset in literal.indices where bytes[index + offset] != literal[offset] {
        throw StrictJSONValidationError.invalidJSON
      }
      index += literal.count
    }

    private mutating func registerNode(depth: Int) throws {
      guard
        depth <= StrictJSONValidator.maximumDepth,
        nodeCount < StrictJSONValidator.maximumNodes
      else {
        throw StrictJSONValidationError.invalidJSON
      }
      nodeCount += 1
      if nodeCount.isMultiple(of: 4_096) {
        try Task.checkCancellation()
      }
    }

    private mutating func skipWhitespace() throws {
      while let byte = currentByte, [0x20, 0x09, 0x0A, 0x0D].contains(byte) {
        index += 1
        try checkCancellationPeriodically()
      }
    }

    private mutating func checkCancellationPeriodically() throws {
      if index.isMultiple(of: 4_096) {
        try Task.checkCancellation()
      }
    }

    private var currentByte: UInt8? {
      index < bytes.count ? bytes[index] : nil
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
      guard currentByte == byte else {
        return false
      }
      index += 1
      return true
    }
  }
}
