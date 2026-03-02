using System.Windows;
using LumineFuck.Core;
using LumineFuck.ViewModels;

namespace LumineFuck.Views;

public partial class DomainListWindow : Window
{
    public DomainListWindow(BlockList blockList)
    {
        InitializeComponent();
        DataContext = new DomainListViewModel(blockList);
    }
}
