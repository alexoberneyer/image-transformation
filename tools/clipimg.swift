// Reads and writes images on the macOS pasteboard for the clip-* scripts.
//
// The pasteboard advertises many flavours of the same image at once - a single
// copy can offer PNG, TIFF, JPEG, GIF and AVIF simultaneously - and asking for
// the wrong one silently destroys the payload. Every read here pins a lossless
// flavour, and prefers a file reference over a bitmap when one is present.

import AppKit

let pb = NSPasteboard.general

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("clipimg: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

/// The file the pasteboard points at, if it holds a reference rather than a
/// bitmap.
func pasteboardFileURL() -> URL? {
    var url: URL? = (pb.readObjects(forClasses: [NSURL.self]) as? [URL])?.first
    if url == nil, let s = pb.string(forType: .fileURL) { url = URL(string: s) }
    guard let file = url, file.isFileURL else { return nil }
    return file
}

/// Bytes of a file the pasteboard points at, if it holds a file reference.
/// The transform detects its format from content, so the bytes go through
/// untouched rather than being re-encoded.
func pasteboardFile() -> Data? {
    guard let file = pasteboardFileURL() else { return nil }
    return try? Data(contentsOf: file)
}

/// Packs `rgb` (w*h*3, no padding) into a PNG.
func encodeRgb(_ rgb: [UInt8], _ w: Int, _ h: Int) -> Data? {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h,
        bitsPerSample: 8, samplesPerPixel: 3, hasAlpha: false, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: w * 3, bitsPerPixel: 24
    ), let dst = rep.bitmapData else { return nil }
    rgb.withUnsafeBufferPointer { dst.update(from: $0.baseAddress!, count: w * h * 3) }
    return rep.representation(using: .png, properties: [:])
}

/// Forces 8-bit, alpha-free, profile-free RGB, which is the only shape the
/// transform accepts. Only ever applied to a `to-noise` input: redrawing a
/// noise image through a colour space would rewrite the exact bytes that have
/// to survive.
func normalize(_ data: Data) -> Data? {
    guard let src = NSBitmapImageRep(data: data) else { return nil }
    let w = src.pixelsWide, h = src.pixelsHigh
    guard w > 0, h > 0 else { return nil }

    // Preferred path: the samples are already 8-bit RGB(A), so lift them out
    // verbatim and drop alpha. A drawing context would colour-manage them on
    // the way through, i.e. change the very values being encrypted.
    let format = src.bitmapFormat
    let exotic: NSBitmapImageRep.Format = [.floatingPointSamples, .thirtyTwoBitLittleEndian,
                                           .sixteenBitLittleEndian, .thirtyTwoBitBigEndian,
                                           .sixteenBitBigEndian]
    // The distance between pixels is `bitsPerPixel`, not `samplesPerPixel`:
    // a rep can report three samples and still pad each pixel out to 32 bits.
    let stride = src.bitsPerPixel / 8
    if src.bitsPerSample == 8, !src.isPlanar, format.isDisjoint(with: exotic),
       src.bitsPerPixel % 8 == 0, stride == 3 || stride == 4, let base = src.bitmapData {
        let rowBytes = src.bytesPerRow
        // Alpha (or the padding byte) may lead rather than trail; skip it
        // either way.
        let first = (stride == 4 && format.contains(.alphaFirst)) ? 1 : 0
        var rgb = [UInt8](repeating: 0, count: w * h * 3)
        for y in 0..<h {
            let row = base + y * rowBytes
            for x in 0..<w {
                let s = x * stride + first
                let d = (y * w + x) * 3
                rgb[d] = row[s]
                rgb[d + 1] = row[s + 1]
                rgb[d + 2] = row[s + 2]
            }
        }
        return encodeRgb(rgb, w, h)
    }

    // Anything else - 16-bit, planar, CMYK, indexed - has to be converted, so
    // hand it to CoreGraphics and take the colour-managed result.
    guard let cg = src.cgImage,
          let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8,
                              bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue),
          let base = ctx.data else { return nil }
    ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))

    let pixels = base.bindMemory(to: UInt8.self, capacity: h * ctx.bytesPerRow)
    var rgb = [UInt8](repeating: 0, count: w * h * 3)
    for y in 0..<h {
        let row = pixels + y * ctx.bytesPerRow
        for x in 0..<w {
            let d = (y * w + x) * 3
            rgb[d] = row[x * 4]
            rgb[d + 1] = row[x * 4 + 1]
            rgb[d + 2] = row[x * 4 + 2]
        }
    }
    return encodeRgb(rgb, w, h)
}

let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {

case "paste":
    var data = pasteboardFile() ?? pb.data(forType: .png)
    if data == nil, let tiff = pb.data(forType: .tiff) {
        data = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:])
    }
    guard var out = data else { fail("no image on the clipboard") }
    if args.contains("--normalize") {
        guard let n = normalize(out) else { fail("cannot decode the clipboard image") }
        out = n
    }
    FileHandle.standardOutput.write(out)

case "copy":
    guard args.count > 2 else { fail("usage: clipimg copy <file>|-") }
    // `-` reads stdin, so the restored image can go from the transform to the
    // pasteboard without ever being written to disk.
    let source = args[2]
    let read = source == "-"
        ? FileHandle.standardInput.readDataToEndOfFile()
        : FileManager.default.contents(atPath: source)
    guard let data = read, !data.isEmpty else { fail("cannot read \(source)") }
    pb.clearContents()
    pb.setData(data, forType: .png)
    // Some apps only look for TIFF, so offer both rather than relying on the
    // system to synthesise one.
    if let rep = NSBitmapImageRep(data: data), let tiff = rep.tiffRepresentation {
        pb.setData(tiff, forType: .tiff)
    }

case "copy-file":
    guard args.count > 2 else { fail("usage: clipimg copy-file <path>") }
    let url = URL(fileURLWithPath: args[2]).standardizedFileURL
    guard FileManager.default.fileExists(atPath: url.path) else { fail("no such file: \(url.path)") }
    pb.clearContents()
    // Written eagerly rather than with `writeObjects`, which hands the
    // pasteboard a lazy promise that is never fulfilled once this process
    // exits - leaving an empty clipboard behind.
    pb.setString(url.absoluteString, forType: .fileURL)
    // The old plist type is what several apps still look for when deciding to
    // attach a file rather than inline a bitmap.
    pb.setPropertyList([url.path], forType: NSPasteboard.PasteboardType("NSFilenamesPboardType"))

case "path":
    // Where the clipboard's file reference points, without reading it. The
    // name is what `clip-from-noise` mines for a key-id.
    guard let file = pasteboardFileURL() else { fail("the clipboard holds no file reference") }
    print(file.standardizedFileURL.path)

default:
    fail("usage: clipimg paste [--normalize] | clipimg copy <file>|- | clipimg copy-file <file> | clipimg path")
}
