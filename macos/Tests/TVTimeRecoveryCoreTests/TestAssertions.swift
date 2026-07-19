import Foundation
import Testing

private struct TestAssertionFailure: Error {}

func expectTrue(
  _ expression: @autoclosure () -> Bool,
  _ message: String = ""
) {
  #expect(expression(), Comment(rawValue: message))
}

func expectFalse(
  _ expression: @autoclosure () -> Bool,
  _ message: String = ""
) {
  #expect(!expression(), Comment(rawValue: message))
}

func expectNil<T>(
  _ expression: @autoclosure () -> T?,
  _ message: String = ""
) {
  #expect(expression() == nil, Comment(rawValue: message))
}

func expectEqual<T: Equatable>(
  _ first: @autoclosure () -> T,
  _ second: @autoclosure () -> T,
  _ message: String = ""
) {
  #expect(first() == second(), Comment(rawValue: message))
}

func expectNotEqual<T: Equatable>(
  _ first: @autoclosure () -> T,
  _ second: @autoclosure () -> T,
  _ message: String = ""
) {
  #expect(first() != second(), Comment(rawValue: message))
}

func expectGreaterThan<T: Comparable>(
  _ first: @autoclosure () -> T,
  _ second: @autoclosure () -> T,
  _ message: String = ""
) {
  #expect(first() > second(), Comment(rawValue: message))
}

func expectNoThrow<T>(
  _ expression: @autoclosure () throws -> T,
  _ message: String = ""
) {
  do {
    _ = try expression()
  } catch {
    let detail = message.isEmpty ? "Unexpected error: \(error)" : message
    #expect(Bool(false), Comment(rawValue: detail))
  }
}

func expectThrowsError<T>(
  _ expression: @autoclosure () throws -> T,
  _ message: String = "",
  file: StaticString = #filePath,
  line: UInt = #line,
  _ errorHandler: (Error) -> Void = { _ in }
) {
  do {
    _ = try expression()
    let detail = message.isEmpty ? "Expected an error" : message
    #expect(Bool(false), Comment(rawValue: detail))
  } catch {
    errorHandler(error)
  }
}

@discardableResult
func requireValue<T>(
  _ expression: @autoclosure () throws -> T?,
  _ message: String = ""
) throws -> T {
  guard let value = try expression() else {
    let detail = message.isEmpty ? "Expected a non-nil value" : message
    #expect(Bool(false), Comment(rawValue: detail))
    throw TestAssertionFailure()
  }
  return value
}

func failTest(
  _ message: String = "",
  file: StaticString = #filePath,
  line: UInt = #line
) {
  let detail = message.isEmpty ? "Test failed" : message
  #expect(Bool(false), Comment(rawValue: detail))
}
