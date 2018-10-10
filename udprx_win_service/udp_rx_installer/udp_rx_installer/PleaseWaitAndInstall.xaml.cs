﻿using System;
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
using System.Threading;
using System.IO;
using System.Reflection;
using System.Diagnostics;

namespace udp_rx_installer
{
    /// <summary>
    /// Interaction logic for PleaseWaitAndInstall.xaml
    /// </summary>
    public partial class PleaseWaitAndInstall : Page
    {
        public PleaseWaitAndInstall()
        {
            InitializeComponent();
            InstallUdpRx();            
        }

        private async void InstallUdpRx()
        {
            var ir = new udp_rx_install_runner();
            await Task.Run(() => ir.RunInstaller("", "", ""));
            this.NavigationService.Navigate(new Finished());
        }
    }

    public class udp_rx_install_runner
    {
        public enum StartupType { Manual, Automatic, AutomaticDelayed}
        string _programfilespath;
        string _programdatapath;
        StartupType _startType;
        public udp_rx_install_runner(string ExePath = "c:\\program files\\udp_rx", string ConfAndKeysPath = "c:\\programdata\\udp_rx", StartupType startType = StartupType.Manual)
        {
            //TODO: validate paths
            _programfilespath = ExePath;
            _programdatapath = ConfAndKeysPath;
            _startType = startType;
        }

        public void RunInstaller(string cafilepath, string devkeyfilepath, string devcertfilepath)
        {
            //make the required directories
            Directory.CreateDirectory(_programfilespath);
            Directory.CreateDirectory(_programdatapath);
            //write the exe to the exe path
            Assembly assembly = this.GetType().Assembly;
            using (Stream input = assembly.GetManifestResourceStream("udp_rx_installer.udprx_win_service.exe"))
            using (Stream output = File.Create(_programfilespath + "\\udprx_win_service.exe"))
            {
                CopyStream(input, output);
            }
            //write the secrets to the programdata path
            string[] tocheck = { "cafile", "key", "cert" };
            foreach (var check in tocheck)
            {
                string filepath = (string)App.Current.Properties[check];
                if (File.Exists(filepath))
                {
                    var filename = System.IO.Path.GetFileName(filepath);
                    File.Copy(filepath, String.Format("{0}\\{1}", _programdatapath, filename), true);
                }
            }
            //write the config file to the programdata path
            using (Stream input = assembly.GetManifestResourceStream("udp_rx_installer.udp_rx_conf.json"))
            using (Stream output = File.Create(_programdatapath + "\\udp_rx_conf.json"))
            {
                CopyStream(input, output);
            }
            //install the service
            var exepath = _programfilespath + "\\udprx_win_service.exe";
            InstallService(exepath);
            //if the start type is anything but 
            Console.WriteLine("DONE!");
        }

        static void InstallService(string exepath)
        {
            Process process = new System.Diagnostics.Process();
            ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = String.Format("/C \"{0}\" install", exepath);
            process.StartInfo = startInfo;
            process.Start();
        }

        static void ServiceStartup(StartupType type)
        {
            Process process = new System.Diagnostics.Process();
            ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            //process start type
            string startstring = "";
            if (type == StartupType.Automatic) startstring = "auto";
            else if (type == StartupType.AutomaticDelayed) startstring = "delayed-auto";
            else if (type == StartupType.Manual) startstring = "demand";
            else return;
            //run command
            startInfo.Arguments = String.Format("/C sc config udp_rx start= {0}", startstring);
            process.StartInfo = startInfo;
            process.Start();
        }

        static void CopyStream(Stream input, Stream output)
        {
            // Insert null checking here for production
            byte[] buffer = new byte[8192];

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, bytesRead);
            }
        }
    }
}
