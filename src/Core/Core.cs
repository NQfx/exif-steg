//namespace Steganography.Shared;
using Steganography.Shared;
using System;
using System.IO;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using static System.Runtime.InteropServices.JavaScript.JSType;
public class Core {
    public string Path { get; }

    public AppSegment? App1Segment { get; private set; }

    public Core(string path) {

        if (!File.Exists(path)) throw new FileNotFoundException(path);
        if (FileAnalysis.GetFileFormat(path) != FileFormat.Jpeg) throw new InvalidOperationException("Only JPEG supported");
        Path = path;

        LoadApp1();
        
        if (App1Segment == null) return;
       
    }
    public string Read(bool isNeedReload) {
        if (isNeedReload) { //если происходит чтение после записи
            LoadApp1();
        }
        return Encoding.UTF8.GetString(App1Segment.Data);
    }

   private void LoadApp1() {
        var segments = FileAnalysis.GetJpegAppSegments(Path);
        App1Segment = new AppSegment();
        App1Segment = segments.Where(s => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0").First();
        
    }
    public void DeleteOurApp1() {
        Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(""), Path, true);
    }
    public void Write(string text) {
        Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(text), Path);
    }

}