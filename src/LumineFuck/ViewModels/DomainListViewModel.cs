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

    public bool BlockAzure
    {
        get => _blockList.BlockAzure;
        set
        {
            if (_blockList.BlockAzure == value) return;
            _blockList.BlockAzure = value;
            OnPropertyChanged();
        }
    }

    public int UnblockAfterSeconds
    {
        get => _blockList.UnblockAfterSeconds;
        set
        {
            if (_blockList.UnblockAfterSeconds == value) return;
            _blockList.UnblockAfterSeconds = value;
            OnPropertyChanged();
        }
    }

    public int BlockDelaySeconds
    {
        get => _blockList.BlockDelaySeconds;
        set
        {
            if (_blockList.BlockDelaySeconds == value) return;
            _blockList.BlockDelaySeconds = value;
            OnPropertyChanged();
        }
    }

    public bool ShowNotifications
    {
        get => _blockList.ShowNotifications;
        set
        {
            if (_blockList.ShowNotifications == value) return;
            _blockList.ShowNotifications = value;
            OnPropertyChanged();
        }
    }

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
