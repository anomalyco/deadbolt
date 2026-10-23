// Headless icon generation: the site's keyhole, red on black.
import AppKit

let size = 1024
let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
NSColor(calibratedWhite: 0.035, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 60, y: 60, width: 904, height: 904),
    xRadius: 200, yRadius: 200).fill()
NSColor(calibratedRed: 0.94, green: 0.18, blue: 0.16, alpha: 1).setFill()
NSBezierPath(ovalIn: NSRect(x: 352, y: 482, width: 320, height: 320)).fill()
let stem = NSBezierPath()
stem.move(to: NSPoint(x: 451, y: 534))
stem.line(to: NSPoint(x: 573, y: 534))
stem.line(to: NSPoint(x: 632, y: 244))
stem.line(to: NSPoint(x: 392, y: 244))
stem.close()
stem.fill()
NSGraphicsContext.restoreGraphicsState()
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
