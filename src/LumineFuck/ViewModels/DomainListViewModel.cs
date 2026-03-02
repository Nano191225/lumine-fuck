using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LumineFuck.Core;

namespace LumineFuck.ViewModels;

public partial class DomainListViewModel : ObservableObject
{
    private readonly BlockList _blockList;

    [ObservableProperty]
    private string _newDomainText = "";

    [ObservableProperty]
    private string _newIpText = "";

    [ObservableProperty]
    private string? _selectedDomain;

    [ObservableProperty]
    private string? _selectedIp;

    public ObservableCollection<string> Domains { get; } = new();
    public ObservableCollection<string> BlockedIps { get; } = new();

    public DomainListViewModel(BlockList blockList)
    {
        _blockList = blockList;
        Reload();
    }

    // --- Domain commands ---

    [RelayCommand]
    private void AddDomain()
    {
        if (string.IsNullOrWhiteSpace(NewDomainText)) return;
        _blockList.AddDomain(NewDomainText);
        NewDomainText = "";
        Reload();
    }

    [RelayCommand]
    private void RemoveDomain()
    {
        if (SelectedDomain == null) return;
        _blockList.RemoveDomain(SelectedDomain);
        Reload();
    }

    // --- IP commands ---

    [RelayCommand]
    private void AddIp()
    {
        if (string.IsNullOrWhiteSpace(NewIpText)) return;
        _blockList.AddIp(NewIpText);
        NewIpText = "";
        Reload();
    }

    [RelayCommand]
    private void RemoveIp()
    {
        if (SelectedIp == null) return;
        _blockList.RemoveIp(SelectedIp);
        Reload();
    }

    private void Reload()
    {
        Domains.Clear();
        foreach (var domain in _blockList.Domains)
            Domains.Add(domain);

        BlockedIps.Clear();
        foreach (var ip in _blockList.BlockedIps)
            BlockedIps.Add(ip);
    }
}
