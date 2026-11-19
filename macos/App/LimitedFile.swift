import Foundation
import Darwin

// Inspect the opened descriptor, not a preceding path stat: a selected file may
// grow or be replaced between selection and reading. Never follow symlinks or
// block opening special files such as FIFOs. Return at most the declared limit.
enum LimitedFile {
    static func read(_ url: URL, maxBytes: Int) throws -> Data {
        guard url.isFileURL, maxBytes > 0, maxBytes < Int.max else { throw ClientError.message("无效的文件读取请求") }
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw ClientError.message("无法打开文件；请使用普通文件，不要使用符号链接") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_size >= 0, metadata.st_size <= maxBytes else { throw ClientError.message("文件类型不支持或内容超过大小限制") }
        var data = Data()
        while data.count <= maxBytes {
            let chunk = try handle.read(upToCount: min(65536, maxBytes + 1 - data.count)) ?? Data()
            if chunk.isEmpty { return data }
            data.append(chunk)
            guard data.count <= maxBytes else { throw ClientError.message("文件内容超过大小限制") }
        }
        throw ClientError.message("文件内容超过大小限制")
    }
}
