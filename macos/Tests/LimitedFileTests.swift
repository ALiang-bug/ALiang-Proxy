import Foundation
import Darwin

func runLimitedFileTests() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("PrivateProxy-file-tests-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let ordinary = directory.appendingPathComponent("ordinary.yaml")
    let boundary = Data(repeating: 0x61, count: 1_048_576)
    try boundary.write(to: ordinary)
    guard try LimitedFile.read(ordinary, maxBytes: boundary.count) == boundary else { fatalError("exact size boundary corrupted") }
    var rejected = 0
    let link = directory.appendingPathComponent("link.yaml")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: ordinary)
    let fifo = directory.appendingPathComponent("fifo.yaml")
    guard mkfifo(fifo.path, 0o600) == 0 else { fatalError("fixture FIFO creation failed") }
    for url in [link, fifo, directory, directory.appendingPathComponent("missing.yaml")] {
        do { _ = try LimitedFile.read(url, maxBytes: boundary.count) } catch { rejected += 1 }
    }
    try (boundary + Data([0x61])).write(to: ordinary)
    do { _ = try LimitedFile.read(ordinary, maxBytes: boundary.count) } catch { rejected += 1 }
    guard rejected == 5 else { fatalError("unsafe or oversized file accepted") }
    print("Limited file reading: exact 1 MiB accepted; oversized file, symlink, FIFO, directory and missing path rejected. Temporary fixtures removed.")
}
