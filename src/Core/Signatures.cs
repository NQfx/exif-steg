namespace Steganography.Core;

public static class Signatures
{
    public const byte Signature = 0x92;
    public const byte EncryptedDataMarker = 0xF2;
    public const byte UnencryptedDataMarker = 0xF1;
}