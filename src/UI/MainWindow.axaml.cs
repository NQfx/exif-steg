using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System;
using System.IO;
using System.Linq;

namespace Steganography.UI;

public partial class MainWindow : Window
{
    private string? _filePath;
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

            FilePathTextBox.Text = localPath;

            string extension = Path.GetExtension(localPath);

            if (!string.IsNullOrEmpty(extension))
            {
                _filePath = localPath;
                FileFormatTextBlock.Text = extension.TrimStart('.').ToUpper();
                Console.WriteLine($"> File has been selected {_filePath}");
            }
            else
            {
                FileFormatTextBlock.Text = "UNKNOWN";
            }
        }
    }

    private void ChangeModeToRead_Click(object? sender, RoutedEventArgs e)
    {
        
    }
}