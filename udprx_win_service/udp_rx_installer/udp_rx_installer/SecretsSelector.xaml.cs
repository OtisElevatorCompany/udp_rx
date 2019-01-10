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
using System.Collections;

namespace udp_rx_installer
{
    /// <summary>
    /// Interaction logic for SecretsSelector.xaml
    /// </summary>
    public partial class SecretsSelector : Page
    {
        private bool skipCerts { get; set; } = false;
        private string[] tocheck = { "cafile", "key", "cert" };
        private Hashtable backup_vals = new Hashtable();

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
            string filetype = "";
            if(sender is Button)
            {
                var senderButton = (Button)sender;
                if ((senderButton).Name.StartsWith("ca")) filetype = "cafile";
                else if ((senderButton).Name.StartsWith("devkey")) filetype = "key";
                else if ((senderButton).Name.StartsWith("devcert")) filetype = "cert";
            }
            else if(sender is TextBox)
            {
                var senderBox = (TextBox)sender;
                if ((senderBox).Name.StartsWith("ca")) filetype = "cafile";
                else if ((senderBox).Name.StartsWith("devkey")) filetype = "key";
                else if ((senderBox).Name.StartsWith("devcert")) filetype = "cert";
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
            //end new
            CheckFiles();
        }

        private void CheckFiles()
        {
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

        private void SkipClick_Click(object sender, RoutedEventArgs e)
        {
            if(SkipCertsBox.IsChecked == true)
            {
                skipCerts = true;
                //disable textboxes
                ca_textbox.IsEnabled = false;
                devcert_textbox.IsEnabled = false;
                devkey_textbox.IsEnabled = false;
                //disable buttons
                ca_button.IsEnabled = false;
                devcert_button.IsEnabled = false;
                devkey_button.IsEnabled = false;
                //move values out
                foreach (var check in tocheck)
                {
                    if(backup_vals.ContainsKey(check))
                    {
                        backup_vals[check] = (string)App.Current.Properties[check];
                    }
                    else
                    {
                        backup_vals.Add(check, (string)App.Current.Properties[check]);
                    }
                    App.Current.Properties[check] = "";
                }
                this.next_button.IsEnabled = true;
            }
            else
            {
                skipCerts = false;
                foreach (var check in tocheck)
                {
                    if (backup_vals.ContainsKey(check))
                    {
                        App.Current.Properties[check] = backup_vals[check];
                    }
                }
                CheckFiles();
            }
        }
    }
}
