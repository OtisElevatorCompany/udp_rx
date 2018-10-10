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
    /// Interaction logic for Finished.xaml
    /// </summary>
    public partial class Finished : Page
    {
        public Finished()
        {
            InitializeComponent();
        }

        private void done_click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}
