namespace Steganography.Shared.Utils;

public static class Crc32 
{
    public static uint ComputeCrc32(byte[] data)
    {
        const uint polynomial = 0xEDB88320;
        uint crc = 0xFFFFFFFF;

        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
        }

        return ~crc;
    }
}