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

namespace udp_rx_installer
{
    /// <summary>
    /// Interaction logic for InstallDirAndType.xaml
    /// </summary>
    public partial class InstallDirAndType : Page
    {
        public InstallDirAndType()
        {
            InitializeComponent();
        }

        private void Next_Click(object sender, RoutedEventArgs e)
        {
            var selectedStartTypeString = (string)ServiceStartCombo.SelectionBoxItem;
            App.Current.Properties["serviceStartType"] = selectedStartTypeString;
            this.NavigationService.Navigate(new SecretsSelector());
        }

        private void Previous_Click(object sender, RoutedEventArgs e)
        {
            this.NavigationService.GoBack();
            //Console.WriteLine("Previous clicked");
        }
        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            MessageBoxResult messageBoxResult = System.Windows.MessageBox.Show("Are you sure you want to quit?", "Quit Confirmation", System.Windows.MessageBoxButton.YesNo);
            if (messageBoxResult == MessageBoxResult.Yes)
            {
                Application.Current.Shutdown();
            }
        }
    }
}
