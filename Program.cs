using System;
using System.IO;
using System.Security.Cryptography;

namespace RLUPKReverse
{
    public class FPackageFileSummary
    {
        private const uint PACKAGE_FILE_TAG = 0x9E2A83C1;

        public ushort LicenseeVersion;
        public int TotalHeaderSize;
        public int NameOffset;
        public int ExportOffset;
        public int GarbageSize;
        public int CompressedChunkInfoOffset;
        public int LastBlockSize;

        public void Deserialize(BinaryReader Reader)
        {
            var Tag = Reader.ReadUInt32();
            if (Tag != PACKAGE_FILE_TAG)
                throw new Exception("Not a valid Unreal Engine package.");

            Reader.ReadUInt16(); // FileVersion
            LicenseeVersion = Reader.ReadUInt16();

            TotalHeaderSize = Reader.ReadInt32();

            // FolderName (FString)
            var FolderNameLen = Reader.ReadInt32();
            if (FolderNameLen > 0) Reader.ReadBytes(FolderNameLen);
            else if (FolderNameLen < 0) Reader.ReadBytes(-FolderNameLen * 2);

            Reader.ReadUInt32(); // PackageFlags

            Reader.ReadInt32(); // NameCount
            NameOffset = Reader.ReadInt32();

            Reader.ReadInt32(); // ExportCount
            ExportOffset = Reader.ReadInt32();

            Reader.ReadInt32(); // ImportCount
            Reader.ReadInt32(); // ImportOffset
            Reader.ReadInt32(); // DependsOffset

            // 4 unknowns
            Reader.ReadInt32(); Reader.ReadInt32();
            Reader.ReadInt32(); Reader.ReadInt32();

            // FGuid
            Reader.ReadUInt32(); Reader.ReadUInt32();
            Reader.ReadUInt32(); Reader.ReadUInt32();

            // Generations TArray
            var GenCount = Reader.ReadInt32();
            for (var i = 0; i < GenCount; i++)
            {
                Reader.ReadInt32(); Reader.ReadInt32(); Reader.ReadInt32();
            }

            Reader.ReadUInt32(); // EngineVersion
            Reader.ReadUInt32(); // CookerVersion
            Reader.ReadUInt32(); // CompressionFlags

            // CompressedChunks TArray
            var ChunkCount = Reader.ReadInt32();
            for (var i = 0; i < ChunkCount; i++)
            {
                if (LicenseeVersion >= 22) { Reader.ReadInt64(); Reader.ReadInt32(); Reader.ReadInt64(); Reader.ReadInt32(); }
                else { Reader.ReadInt32(); Reader.ReadInt32(); Reader.ReadInt32(); Reader.ReadInt32(); }
            }

            Reader.ReadInt32(); // Unknown5

            // UnknownStringArray
            var StrCount = Reader.ReadInt32();
            for (var i = 0; i < StrCount; i++)
            {
                var Len = Reader.ReadInt32();
                if (Len > 0) Reader.ReadBytes(Len);
                else if (Len < 0) Reader.ReadBytes(-Len * 2);
            }

            // UnknownTypeArray
            var UnkCount = Reader.ReadInt32();
            for (var i = 0; i < UnkCount; i++)
            {
                Reader.ReadInt32(); Reader.ReadInt32(); Reader.ReadInt32();
                Reader.ReadInt32(); Reader.ReadInt32();
                var ArrLen = Reader.ReadInt32();
                for (var j = 0; j < ArrLen; j++) Reader.ReadInt32();
            }

            GarbageSize = Reader.ReadInt32();
            CompressedChunkInfoOffset = Reader.ReadInt32();
            LastBlockSize = Reader.ReadInt32();
        }
    }

    class Program
    {
        public static byte[] AESKey =
        {
            0xC7, 0xDF, 0x6B, 0x13, 0x25, 0x2A, 0xCC, 0x71,
            0x47, 0xBB, 0x51, 0xC9, 0x8A, 0xD7, 0xE3, 0x4B,
            0x7F, 0xE5, 0x00, 0xB7, 0x7F, 0xA5, 0xFA, 0xB2,
            0x93, 0xE2, 0xF2, 0x4E, 0x6B, 0x17, 0xE7, 0x79
        };

        private static byte[] Encrypt(byte[] Buffer)
        {
            var Rijndael = new RijndaelManaged
            {
                KeySize = 256,
                Key = AESKey,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };

            return Rijndael.CreateEncryptor().TransformFinalBlock(Buffer, 0, Buffer.Length);
        }

        private static byte[] Decrypt(byte[] Buffer)
        {
            var Rijndael = new RijndaelManaged
            {
                KeySize = 256,
                Key = AESKey,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };

            return Rijndael.CreateDecryptor().TransformFinalBlock(Buffer, 0, Buffer.Length);
        }

        private static void ProcessFile(string DecryptedPath, string OriginalPath, string OutPath)
        {
            var DecryptedData = File.ReadAllBytes(DecryptedPath);
            var OriginalData = File.ReadAllBytes(OriginalPath);

            // Parse the summary from the original encrypted file
            // (we use the original because its header is untouched)
            FPackageFileSummary Sum;
            using (var MS = new MemoryStream(OriginalData))
            using (var Reader = new BinaryReader(MS))
            {
                Sum = new FPackageFileSummary();
                Sum.Deserialize(Reader);
            }

            var PayloadSize = Sum.TotalHeaderSize - Sum.GarbageSize - Sum.NameOffset;
            var PaddedSize = (PayloadSize + 15) & ~15;

            // Pull the encrypted payload from the original file and decrypt it
            // This gives us clean plaintext that we can re-encrypt
            var RawEncrypted = new byte[PaddedSize];
            Array.Copy(OriginalData, Sum.NameOffset, RawEncrypted, 0, PaddedSize);
            var PlainText = Decrypt(RawEncrypted);

            // Re-encrypt it (round trip test - output should be identical to original)
            var ReEncrypted = Encrypt(PlainText);

            // Write output file
            using (var Output = new FileStream(OutPath, FileMode.Create))
            {
                // 1. Unencrypted file summary from the original
                Output.Write(OriginalData, 0, Sum.NameOffset);

                // 2. Re-encrypted payload (only PayloadSize bytes, not the padded size)
                Output.Write(ReEncrypted, 0, PayloadSize);

                // 3. Garbage bytes from the original
                if (Sum.GarbageSize > 0)
                {
                    var GarbageStart = Sum.TotalHeaderSize - Sum.GarbageSize;
                    Output.Write(OriginalData, GarbageStart, Sum.GarbageSize);
                }

                // 4. Compressed chunk data from the original
                var ChunkDataStart = Sum.TotalHeaderSize;
                var ChunkDataLength = OriginalData.Length - ChunkDataStart;
                if (ChunkDataLength > 0)
                    Output.Write(OriginalData, ChunkDataStart, ChunkDataLength);
            }

            Console.WriteLine($"Done: {OutPath}");
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: RLUPKReverse <decrypted.upk> <original_encrypted.upk>");
                return;
            }

            var DecryptedPath = args[0];
            var OriginalPath = args[1];

            if (!DecryptedPath.EndsWith("_decrypted.upk"))
            {
                Console.Error.WriteLine("First argument should be the _decrypted.upk file.");
                return;
            }

            if (OriginalPath.EndsWith("_decrypted.upk"))
            {
                Console.Error.WriteLine("Second argument should be the original encrypted .upk file.");
                return;
            }

            var OutPath = DecryptedPath.Replace("_decrypted.upk", "_reencrypted.upk");
            ProcessFile(DecryptedPath, OriginalPath, OutPath);
        }
    }
}