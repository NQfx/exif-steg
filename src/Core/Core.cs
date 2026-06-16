using Steganography.Shared;
using System.Text;

public class CoreObject {
    public string Path { get; }

    public AppSegment? App1Segment { get; private set; }

    public CoreObject(string path) {

        if (!File.Exists(path)) throw new FileNotFoundException(path);
        if (FileAnalysis.GetFileFormat(path) != FileFormat.Jpeg) 
            throw new InvalidOperationException("Only JPEG supported");
        Path = path;

        LoadApp1();
        
        if (App1Segment == null) return;
       
    }
    public string Read(bool isNeedReload) {
        LoadApp1();
        if (App1Segment.Data != null) return Encoding.UTF8.GetString(App1Segment.Data);
        else return string.Empty;

    }

   private void LoadApp1() {
        var segments = FileAnalysis.GetJpegAppSegments(Path);
        App1Segment = new AppSegment();
        App1Segment = segments.Where(s => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0\0").FirstOrDefault();
        
    }
    public void DeleteOurApp1() {
        Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(""), Path, true);
    }
    public void Write(string text) {
        Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(text), Path);
    }

}