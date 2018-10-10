using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
//using Microsoft.WindowsAPICodePack.Dialogs;
using System.Diagnostics;
using System.IO;

namespace udp_rx_installer
{
    /// <summary>
    /// Interaction logic for SecretsSelector.xaml
    /// </summary>
    public partial class SecretsSelector : Page
    {
        public bool ValidFiles { get; set; } = false;
#if DEBUG
        //public string SecretsDirectory { get; set; } = @"C:\Users\jeremymill\Documents\dev_secrets";
        public string SecretsDirectory { get; set; } = @"C:\";
#else
        //public string SecretsDirectory { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        public string SecretsDirectory { get; set; } = System.AppDomain.CurrentDomain.BaseDirectory;
#endif



        public SecretsSelector()
        {
            InitializeComponent();
        }
        private void Next_Click(object sender, RoutedEventArgs e)
        {
            this.NavigationService.Navigate(new PleaseWaitAndInstall());
        }

        private void Previous_Click(object sender, RoutedEventArgs e)
        {
            this.NavigationService.GoBack();
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            MessageBoxResult messageBoxResult = System.Windows.MessageBox.Show("Are you sure you want to quit?", "Quit Confirmation", System.Windows.MessageBoxButton.YesNo);
            if (messageBoxResult == MessageBoxResult.Yes)
            {
                Application.Current.Shutdown();
            }
        }

        private void textboxclick(object sender, MouseButtonEventArgs e)
        {
            InputFileButtonClick(sender, e);
        }

        private void InputFileButtonClick(object sender, RoutedEventArgs e)
        {
            Console.WriteLine("Input file clicked");
            bool successSelect = false;
            string filetype = "";
            if(sender is Button)
            {
                if (((Button)sender).Name.StartsWith("ca")) filetype = "cafile";
                else if (((Button)sender).Name.StartsWith("devkey")) filetype = "key";
                else if (((Button)sender).Name.StartsWith("devcert")) filetype = "cert";
            }
            else if(sender is TextBox)
            {
                if (((TextBox)sender).Name.StartsWith("ca")) filetype = "cafile";
                else if (((TextBox)sender).Name.StartsWith("devkey")) filetype = "key";
                else if (((TextBox)sender).Name.StartsWith("devcert")) filetype = "cert";
            }
            if (filetype == "")
            {
                return;
            }
            Console.WriteLine("Filetype is: ", filetype);
            //testing new 
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog();
            openFileDialog.InitialDirectory = SecretsDirectory;
            if (openFileDialog.ShowDialog() == true)
            {
                App.Current.Properties[filetype] = openFileDialog.FileName;
                if (filetype == "cafile") ca_textbox.Text = (string)App.Current.Properties[filetype];
                else if (filetype == "key") devkey_textbox.Text = (string)App.Current.Properties[filetype];
                else if (filetype == "cert") devcert_textbox.Text = (string)App.Current.Properties[filetype];
                SecretsDirectory = System.IO.Path.GetDirectoryName(openFileDialog.FileName);
            }
            //txtEditor.Text = File.ReadAllText(openFileDialog.FileName);
            //end new
            //use the modern if available:
            //if (CommonFileDialog.IsPlatformSupported)
            //{
            //    var folderSelectorDialog = new CommonOpenFileDialog();
            //    folderSelectorDialog.EnsureReadOnly = true;
            //    folderSelectorDialog.IsFolderPicker = false;
            //    folderSelectorDialog.AllowNonFileSystemItems = false;
            //    folderSelectorDialog.Multiselect = false;
            //    folderSelectorDialog.InitialDirectory = SecretsDirectory;
            //    folderSelectorDialog.Title = "Input File";
            //    var folderresult = folderSelectorDialog.ShowDialog();
            //    if (folderresult == CommonFileDialogResult.Ok)
            //    {
            //        App.Current.Properties[filetype] = folderSelectorDialog.FileName;
            //        SecretsDirectory = System.IO.Path.GetDirectoryName(folderSelectorDialog.FileName);
            //        successSelect = true;
            //    }
            //}
            ////create open folder dialog
            //else
            //{
            //    using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            //    {
            //        var folderresult = dialog.ShowDialog();
            //        if (folderresult == System.Windows.Forms.DialogResult.OK)
            //        {
            //            App.Current.Properties[filetype] = dialog.SelectedPath;
            //            successSelect = true;
            //        }
            //    }
            //}
            //if (successSelect)
            //{
            //    //inputfile_textbox.Text = input_dir;
            //    if (filetype == "cafile") ca_textbox.Text = (string)App.Current.Properties[filetype];
            //    else if (filetype == "key") devkey_textbox.Text = (string)App.Current.Properties[filetype];
            //    else if (filetype == "cert") devcert_textbox.Text = (string)App.Current.Properties[filetype];
            //}
            CheckFiles();
        }

        private void CheckFiles()
        {
            string[] tocheck = { "cafile", "key", "cert" };
            foreach(var check in tocheck)
            {
                if(!File.Exists((string)App.Current.Properties[check]))
                {
                    this.next_button.IsEnabled = false;
                    return;
                }
            }
            this.next_button.IsEnabled = true;
        }
    }
}
