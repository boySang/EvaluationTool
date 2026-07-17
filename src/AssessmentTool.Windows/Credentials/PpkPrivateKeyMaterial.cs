using System;
using System.Collections.Generic;
using System.Text;

namespace AssessmentTool.Windows.Credentials;

public enum PpkPrivateKeyFailure
{
    Empty,
    TooLarge,
    UnsupportedFormat,
    Encrypted,
    InvalidText,
    InvalidStructure
}

public sealed class PpkPrivateKeyException : Exception
{
    internal PpkPrivateKeyException(PpkPrivateKeyFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public PpkPrivateKeyFailure Failure { get; }
}

public static class PpkPrivateKeyMaterial
{
    public const int MaximumEncodedBytes = 256 * 1024;
    private const int MaximumLineLength = 4096;
    private const int MaximumCommentLength = 1024;
    private const int MaximumBase64Lines = 4096;
    private const int MaximumBase64LineLength = 64;
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    public static void Validate(char[] material)
    {
        if (material == null)
        {
            throw new ArgumentNullException(nameof(material));
        }

        if (material.Length == 0)
        {
            throw Failure(PpkPrivateKeyFailure.Empty, "PuTTY 私钥内容为空。");
        }

        int encodedLength;
        try
        {
            encodedLength = StrictUtf8.GetByteCount(material);
        }
        catch (EncoderFallbackException)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidText, "PuTTY 私钥包含无效的 Unicode 文本。");
        }

        if (encodedLength > MaximumEncodedBytes)
        {
            throw Failure(PpkPrivateKeyFailure.TooLarge, "PuTTY 私钥超过允许的大小限制。");
        }

        var lines = ReadLines(material);
        if (lines.Count == 0)
        {
            throw Failure(PpkPrivateKeyFailure.Empty, "PuTTY 私钥内容为空。");
        }

        var index = 0;
        var version = ReadHeader(material, lines[index++]);
        RequireField(material, Next(lines, ref index), "Encryption: ", "none", encryptedField: true);
        RequireComment(material, Next(lines, ref index));

        var publicLineCount = ReadLineCount(material, Next(lines, ref index), "Public-Lines: ");
        ValidateBase64Block(material, lines, ref index, publicLineCount);

        var privateLineCount = ReadLineCount(material, Next(lines, ref index), "Private-Lines: ");
        ValidateBase64Block(material, lines, ref index, privateLineCount);

        var expectedMacLength = version == 2 ? 40 : 64;
        RequireHexField(material, Next(lines, ref index), "Private-MAC: ", expectedMacLength);
        if (index != lines.Count)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥包含未识别的额外字段。");
        }
    }

    private static List<LineRange> ReadLines(char[] material)
    {
        var lines = new List<LineRange>();
        var start = 0;
        for (var index = 0; index < material.Length; index++)
        {
            var character = material[index];
            if (character == '\0' || character == '\uFEFF' || char.IsSurrogate(character)
                || (char.IsControl(character) && character != '\r' && character != '\n'))
            {
                throw Failure(PpkPrivateKeyFailure.InvalidText, "PuTTY 私钥包含不允许的控制字符。");
            }

            if (character == '\r')
            {
                if (index + 1 >= material.Length || material[index + 1] != '\n')
                {
                    throw Failure(PpkPrivateKeyFailure.InvalidText, "PuTTY 私钥包含异常换行符。");
                }

                AddLine(lines, start, index - start);
                index++;
                start = index + 1;
            }
            else if (character == '\n')
            {
                AddLine(lines, start, index - start);
                start = index + 1;
            }
        }

        if (start < material.Length)
        {
            AddLine(lines, start, material.Length - start);
        }

        return lines;
    }

    private static void AddLine(ICollection<LineRange> lines, int start, int length)
    {
        if (length == 0)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥包含空行或结构不完整。");
        }

        if (length > MaximumLineLength)
        {
            throw Failure(PpkPrivateKeyFailure.TooLarge, "PuTTY 私钥包含异常长的文本行。");
        }

        lines.Add(new LineRange(start, length));
    }

    private static int ReadHeader(char[] material, LineRange line)
    {
        const string version2Prefix = "PuTTY-User-Key-File-2: ";
        const string version3Prefix = "PuTTY-User-Key-File-3: ";
        int version;
        int valueStart;
        if (StartsWith(material, line, version2Prefix))
        {
            version = 2;
            valueStart = line.Start + version2Prefix.Length;
        }
        else if (StartsWith(material, line, version3Prefix))
        {
            version = 3;
            valueStart = line.Start + version3Prefix.Length;
        }
        else
        {
            throw Failure(PpkPrivateKeyFailure.UnsupportedFormat, "仅支持 PuTTY PPK v2 或 v3 私钥。");
        }

        var valueLength = line.End - valueStart;
        if (valueLength == 0 || valueLength > 128)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥算法标识无效。");
        }

        for (var index = valueStart; index < line.End; index++)
        {
            var character = material[index];
            if (!IsAsciiTokenCharacter(character))
            {
                throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥算法标识无效。");
            }
        }

        return version;
    }

    private static void RequireField(
        char[] material,
        LineRange line,
        string prefix,
        string expectedValue,
        bool encryptedField)
    {
        if (!StartsWith(material, line, prefix))
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥字段顺序或结构无效。");
        }

        var valueStart = line.Start + prefix.Length;
        if (!RangeEquals(material, valueStart, line.End - valueStart, expectedValue))
        {
            throw Failure(
                encryptedField ? PpkPrivateKeyFailure.Encrypted : PpkPrivateKeyFailure.InvalidStructure,
                encryptedField
                    ? "暂不支持带口令加密的 PuTTY PPK 私钥。"
                    : "PuTTY 私钥字段值无效。");
        }
    }

    private static void RequireComment(char[] material, LineRange line)
    {
        const string prefix = "Comment: ";
        if (!StartsWith(material, line, prefix))
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥缺少 Comment 字段。");
        }

        if (line.Length - prefix.Length > MaximumCommentLength)
        {
            throw Failure(PpkPrivateKeyFailure.TooLarge, "PuTTY 私钥注释字段过长。");
        }
    }

    private static int ReadLineCount(char[] material, LineRange line, string prefix)
    {
        if (!StartsWith(material, line, prefix))
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥字段顺序或结构无效。");
        }

        var valueStart = line.Start + prefix.Length;
        var valueLength = line.End - valueStart;
        if (valueLength == 0 || valueLength > 4)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥数据行数无效。");
        }

        var result = 0;
        for (var index = valueStart; index < line.End; index++)
        {
            var character = material[index];
            if (character < '0' || character > '9')
            {
                throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥数据行数无效。");
            }

            result = checked((result * 10) + (character - '0'));
        }

        if (result < 1 || result > MaximumBase64Lines)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥数据行数超出允许范围。");
        }

        return result;
    }

    private static void ValidateBase64Block(
        char[] material,
        IReadOnlyList<LineRange> lines,
        ref int index,
        int count)
    {
        var totalCharacters = 0;
        for (var lineIndex = 0; lineIndex < count; lineIndex++)
        {
            var line = Next(lines, ref index);
            if (line.Length > MaximumBase64LineLength || (lineIndex < count - 1 && line.Length != MaximumBase64LineLength))
            {
                throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥 Base64 数据换行结构无效。");
            }

            var paddingStarted = false;
            var paddingCount = 0;
            for (var characterIndex = line.Start; characterIndex < line.End; characterIndex++)
            {
                var character = material[characterIndex];
                var isPadding = character == '=';
                if (!IsBase64Character(character) && !isPadding)
                {
                    throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥包含无效的 Base64 数据。");
                }

                if (isPadding && (lineIndex != count - 1 || characterIndex < line.End - 2))
                {
                    throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥 Base64 填充位置无效。");
                }

                if (isPadding)
                {
                    paddingStarted = true;
                    paddingCount++;
                }
                else if (paddingStarted)
                {
                    throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥 Base64 填充位置无效。");
                }
            }

            if (paddingCount > 2)
            {
                throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥 Base64 填充长度无效。");
            }

            totalCharacters = checked(totalCharacters + line.Length);
        }

        if (totalCharacters == 0 || totalCharacters % 4 != 0)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥 Base64 数据长度无效。");
        }
    }

    private static void RequireHexField(
        char[] material,
        LineRange line,
        string prefix,
        int expectedLength)
    {
        if (!StartsWith(material, line, prefix))
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥缺少完整性校验字段。");
        }

        var valueStart = line.Start + prefix.Length;
        if (line.End - valueStart != expectedLength)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥完整性校验长度无效。");
        }

        for (var index = valueStart; index < line.End; index++)
        {
            var character = material[index];
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')
                || (character >= 'A' && character <= 'F')))
            {
                throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥完整性校验格式无效。");
            }
        }
    }

    private static LineRange Next(IReadOnlyList<LineRange> lines, ref int index)
    {
        if (index >= lines.Count)
        {
            throw Failure(PpkPrivateKeyFailure.InvalidStructure, "PuTTY 私钥结构不完整。");
        }

        return lines[index++];
    }

    private static bool StartsWith(char[] material, LineRange line, string prefix)
    {
        return line.Length >= prefix.Length && RangeEquals(material, line.Start, prefix.Length, prefix);
    }

    private static bool RangeEquals(char[] material, int start, int length, string expected)
    {
        if (length != expected.Length)
        {
            return false;
        }

        for (var index = 0; index < length; index++)
        {
            if (material[start + index] != expected[index])
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiTokenCharacter(char character)
    {
        return (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character == '-'
            || character == '_'
            || character == '.'
            || character == '@'
            || character == '+';
    }

    private static bool IsBase64Character(char character)
    {
        return (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character == '+'
            || character == '/';
    }

    private static PpkPrivateKeyException Failure(PpkPrivateKeyFailure failure, string message)
    {
        return new PpkPrivateKeyException(failure, message);
    }

    private readonly struct LineRange
    {
        internal LineRange(int start, int length)
        {
            Start = start;
            Length = length;
        }

        internal int Start { get; }
        internal int Length { get; }
        internal int End => Start + Length;
    }
}
