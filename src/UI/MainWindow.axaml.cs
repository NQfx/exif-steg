using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Steganography.Shared;
using System;
using System.IO;
using System.Linq;
using Avalonia;
using System.Collections.ObjectModel;

namespace Steganography.UI;

public partial class MainWindow : Window
{
    public static readonly DirectProperty<MainWindow, string> FilePathProp =
        AvaloniaProperty.RegisterDirect<MainWindow, string>(
            nameof(FilePath),
            o => o.FilePath,
            (o, v) => o.FilePath = v);

    public static readonly DirectProperty<MainWindow, string> FileExtensionProp =
        AvaloniaProperty.RegisterDirect<MainWindow, string>(
            nameof(FileExtension),
            o => o.FileExtension);

    private string _filePath = string.Empty;
    public string FilePath
    {
        get => _filePath;
        set
        {
            var oldFileExtension = FileExtension;

            SetAndRaise(FilePathProp, ref _filePath, value);
            RaisePropertyChanged(FileExtensionProp, oldFileExtension, FileExtension);
        }
    }

    public string FileExtension
    {
        get
        {
            var extension = Path.GetExtension(FilePath);
            var ext = extension.TrimStart('.').ToUpper();
            return ext;
        }
    }

    public static readonly DirectProperty<MainWindow, bool> IsFileLoadedProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(IsFileLoaded),
            o => o.IsFileLoaded,
            (o, v) => o.IsFileLoaded = v);

    public static readonly DirectProperty<MainWindow, bool> IsProcessButtonEnabledProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(IsFileLoaded),
            o => o.IsFileLoaded);

    private bool _isFileLoaded;
    public bool IsFileLoaded
    {
        get => _isFileLoaded;
        set 
        {
            SetAndRaise(IsFileLoadedProp, ref _isFileLoaded, value);
            RaisePropertyChanged(IsProcessButtonEnabledProp, !IsFileLoaded, IsFileLoaded);
        }
    }

    public static readonly DirectProperty<MainWindow, string?> TextProp =
        AvaloniaProperty.RegisterDirect<MainWindow, string?>(
            nameof(Text),
            o => o.Text,
            (o, v) => o.Text = v);

    public static readonly DirectProperty<MainWindow, bool> IsTextFoundProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(IsTextFound),
            o => o.IsTextFound);

    public static readonly DirectProperty<MainWindow, string?> TextBufferProp =
        AvaloniaProperty.RegisterDirect<MainWindow, string?>(
            nameof(TextBuffer),
            o => o.TextBuffer,
            (o, v) => o.TextBuffer = v);
    
    private string? _text;
    public string? Text
    {
        get => _text;
        set
        {
            bool oldIsTextFound = IsTextFound;

            SetAndRaise(TextProp, ref _text, value);
            RaisePropertyChanged(IsTextFoundProp, oldIsTextFound, IsTextFound);
        }
    }

    private string? _textBuffer;
    public string? TextBuffer
    {
        get => _textBuffer;
        set => SetAndRaise(TextBufferProp, ref _textBuffer, value);
    }

    public static readonly DirectProperty<MainWindow, bool> DeleteBlockFlagProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(DeleteBlockFlag),
            o => o.DeleteBlockFlag,
            (o, v) => o.DeleteBlockFlag = v);

    private bool _deleteBlockFlag = false;
    public bool DeleteBlockFlag
    {
        get => _deleteBlockFlag;
        set 
        {
            SetAndRaise(DeleteBlockFlagProp, ref _deleteBlockFlag, value);
            RaisePropertyChanged(DeleteBlockFlagProp, !DeleteBlockFlag, DeleteBlockFlag);
        }
    }

    public static readonly DirectProperty<MainWindow, bool> WrittenFileFlagProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(WrittenFileFlag),
            o => o.WrittenFileFlag,
            (o, v) => o.WrittenFileFlag = v);

    private bool _writtenFileFlag = false;
    public bool WrittenFileFlag
    {
        get => _writtenFileFlag;
        set 
        {
            SetAndRaise(WrittenFileFlagProp, ref _writtenFileFlag, value);
            RaisePropertyChanged(WrittenFileFlagProp, !WrittenFileFlag, WrittenFileFlag);
        }
    }

    public static readonly DirectProperty<MainWindow, bool> FormatErrorFlagProp =
        AvaloniaProperty.RegisterDirect<MainWindow, bool>(
            nameof(FormatErrorFlag),
            o => o.FormatErrorFlag,
            (o, v) => o.FormatErrorFlag = v);

    private bool _formatErrorFlag = false;
    public bool FormatErrorFlag
    {
        get => _formatErrorFlag;
        set 
        {
            SetAndRaise(FormatErrorFlagProp, ref _formatErrorFlag, value);
            RaisePropertyChanged(FormatErrorFlagProp, !FormatErrorFlag, FormatErrorFlag);
        }
    }

    public bool IsTextFound => _text is not null && _text.Length > 0;
    public ObservableCollection<string> SignleBlockList { get; } = new() { "StaticDataBlock" };

    private CoreObject? _core;
    public MainWindow()
    {
        InitializeComponent();
    }

    private async void OpenFileButton_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файл для приложения",
            AllowMultiple = false
        });

        if (files.Count > 0)
        {
            var selectedFile = files.First();
            
            string localPath = selectedFile.Path.LocalPath;

            FilePath = localPath;

            var format = FileAnalysis.GetFileFormat(localPath);

            if (format != FileFormat.Unknown)
            {
                FilePath = localPath;
                _core = new CoreObject(localPath);
                ReadFile(_core);
                FormatErrorFlag = false;
                Console.WriteLine($"> File has been selected {_filePath}");
            }
            else
            {
                FormatErrorFlag = true;
                FileFormatTextBlock.Text = "UNKNOWN";
            }
            WrittenFileFlag = false;
        }
    }

    private void WriteButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_core is null)
            throw new InvalidOperationException();
        if (TextBuffer is null || DeleteBlockFlag)
            _core.Write(string.Empty);
        else
            _core.Write(TextBuffer);
        DeleteBlockFlag = false;
        WrittenFileFlag = true;
    }

    private void CloseFileButton_Click(object? sender, RoutedEventArgs e)
    {
        IsFileLoaded = false;
        FilePath = string.Empty;
        DeleteBlockFlag = false;
        WrittenFileFlag = false;
    }

    private void RemoveBlockButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_core is null)
            throw new InvalidOperationException();
        DeleteBlockFlag = true;
        Text=string.Empty;
        WrittenFileFlag = false;
    }

    private void AddBlockButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_core is null)
            throw new InvalidOperationException();
        Text = "⠀";
        _core.Read(true);
        DeleteBlockFlag = false;
        WrittenFileFlag = false;
    }

    private void ReadFile(CoreObject core)
    {
        Text = core.Read(true);
        TextBuffer = Text;
        IsFileLoaded = true;
    }

}