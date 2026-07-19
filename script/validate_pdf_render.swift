import AppKit
import Foundation
import PDFKit

enum RenderFailure: Error, CustomStringConvertible {
  case invalidInput(String)
  case invalidPage(Int, String)

  var description: String {
    switch self {
    case .invalidInput(let message): message
    case .invalidPage(let page, let message): "page \(page): \(message)"
    }
  }
}

func validatePDF(at url: URL) throws {
  let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
  guard values.isRegularFile == true, values.isSymbolicLink != true,
    let document = PDFDocument(url: url), document.pageCount > 0
  else {
    throw RenderFailure.invalidInput("expected a non-empty regular PDF")
  }
  let firstPageText = document.page(at: 0)?.string ?? ""
  let isSyntheticFixture = firstPageText.contains(
    "SYNTHETIC QA FIXTURE - NOT RECOVERED USER DATA")
  let expectedHeader =
    isSyntheticFixture
    ? "SYNTHETIC QA FIXTURE - NOT USER DATA" : "TV Time private recovery report"
  let expectedFooter =
    isSyntheticFixture
    ? "Synthetic QA fixture - not recovered user data" : "Private - contains viewing history"

  for index in 0..<document.pageCount {
    guard let page = document.page(at: index) else {
      throw RenderFailure.invalidPage(index + 1, "page object was unavailable")
    }
    let bounds = page.bounds(for: .mediaBox)
    guard bounds.width.isFinite, bounds.height.isFinite, bounds.width > 0, bounds.height > 0 else {
      throw RenderFailure.invalidPage(index + 1, "media bounds were invalid")
    }
    let ratio = bounds.width / bounds.height
    guard ratio > 0.70, ratio < 0.72 else {
      throw RenderFailure.invalidPage(index + 1, "page was not A4 portrait")
    }
    let expectedPageNumber = "Page \(index + 1)"
    let extracted = page.string ?? ""
    guard extracted.contains(expectedHeader), extracted.contains(expectedFooter),
      extracted.contains(expectedPageNumber)
    else {
      throw RenderFailure.invalidPage(index + 1, "header/footer text was missing")
    }

    let thumbnail = page.thumbnail(of: NSSize(width: 240, height: 340), for: .mediaBox)
    guard let data = thumbnail.tiffRepresentation, let bitmap = NSBitmapImageRep(data: data) else {
      throw RenderFailure.invalidPage(index + 1, "native rasterization failed")
    }
    var inkCount = 0
    var minimumX = bitmap.pixelsWide
    var minimumY = bitmap.pixelsHigh
    var maximumX = -1
    var maximumY = -1
    for y in 0..<bitmap.pixelsHigh {
      for x in 0..<bitmap.pixelsWide {
        guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else {
          continue
        }
        let visibleInk =
          color.alphaComponent > 0.05
          && (color.redComponent < 0.96 || color.greenComponent < 0.96
            || color.blueComponent < 0.96)
        if visibleInk {
          inkCount += 1
          minimumX = min(minimumX, x)
          minimumY = min(minimumY, y)
          maximumX = max(maximumX, x)
          maximumY = max(maximumY, y)
        }
      }
    }
    guard inkCount > 100 else {
      throw RenderFailure.invalidPage(index + 1, "rendered page was effectively blank")
    }
    guard minimumX > 1, minimumY > 1, maximumX < bitmap.pixelsWide - 2,
      maximumY < bitmap.pixelsHigh - 2
    else {
      throw RenderFailure.invalidPage(index + 1, "rendered content touched a page edge")
    }
  }

  print("Native PDF render passed for \(document.pageCount) pages.")
}

do {
  guard CommandLine.arguments.count == 2 else {
    throw RenderFailure.invalidInput("usage: validate_pdf_render.swift REPORT.pdf")
  }
  try validatePDF(at: URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL)
} catch {
  FileHandle.standardError.write(Data("PDF render validation failed: \(error)\n".utf8))
  exit(1)
}
