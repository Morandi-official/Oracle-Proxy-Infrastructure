using System.Text.Json.Nodes;

namespace OracleProxy.Product;

internal sealed partial class MainForm
{
    private Action? _updateDirectApplicationDialog;
    private bool CanEditDirectApplications=>ActionsAvailable && _authenticated && _lastMode=="disconnected" && !DisconnectAction && !_udpDiagnosing;

    private sealed record ListedDirectApplication(string Path,string Status)
    {
        public override string ToString()=>Status switch{
            "active"=>"直连已启用     "+Path,
            "unavailable"=>"走 VPN，需重新添加     "+Path,
            _=>"已保存     "+Path};
    }

    private void ShowDirectApplications()
    {
        using var dialog=new Form{Name="direct-application-settings",Text="应用直连",StartPosition=FormStartPosition.CenterParent,
            ClientSize=new Size(730,350),MinimumSize=new Size(480,295),MinimizeBox=false,MaximizeBox=false,
            AutoScaleMode=AutoScaleMode.Dpi,BackColor=Canvas,ForeColor=Ink,Font=Font};
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(16),ColumnCount=1,RowCount=4};
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(layout);
        var guidance=new Label{AutoSize=true,ForeColor=Muted,Margin=new Padding(0,0,0,8),Dock=DockStyle.Fill};
        layout.Controls.Add(guidance,0,0);
        var paths=new ListBox{Name="direct-app-paths",AccessibleName="直连应用及当前状态",Dock=DockStyle.Fill,IntegralHeight=false,HorizontalScrollbar=true};
        layout.Controls.Add(paths,0,1);
        var buttons=Actions();layout.Controls.Add(buttons,0,2);
        var add=new SmoothButton{Name="add-direct-app",Text="添加 EXE",Width=115,Height=38};
        var remove=new SmoothButton{Name="remove-direct-app",Text="移除选中项",Width=115,Height=38};
        var close=new SmoothButton{Text="关闭",Width=82,Height=38,DialogResult=DialogResult.Cancel};
        StyleButton(add,true);StyleButton(remove);StyleButton(close);
        buttons.Controls.AddRange([add,remove,close]);dialog.CancelButton=close;
        var status=new Label{Name="direct-app-feedback",AutoSize=true,ForeColor=Muted,Margin=new Padding(0,5,0,0),Dock=DockStyle.Fill};
        layout.Controls.Add(status,0,3);
        bool editing=false;
        void UpdateButtons(){add.Enabled=!editing && CanEditDirectApplications;remove.Enabled=add.Enabled && paths.SelectedItem is ListedDirectApplication;}
        void Render()
        {
            var entries=(_diagnosticSnapshot?["direct_applications"] as JsonArray)?.OfType<JsonObject>().Select(item=>
                new ListedDirectApplication(item["path"]!.GetValue<string>(),item["status"]!.GetValue<string>())).ToArray()??[];
            if(!paths.Items.OfType<ListedDirectApplication>().SequenceEqual(entries)){
                string? selected=(paths.SelectedItem as ListedDirectApplication)?.Path;
                paths.Items.Clear();paths.Items.AddRange(entries);
                paths.SelectedIndex=Array.FindIndex(entries,entry=>StringComparer.OrdinalIgnoreCase.Equals(entry.Path,selected));
            }
            guidance.Text=_lastMode=="disconnected"?"每个 EXE 单独添加，下次连接时生效。程序更新后请重新添加。":"连接期间可查看状态。请在本机断开 VPN 后增删应用。";
            UpdateButtons();
        }
        async Task Change(string command,string path)
        {
            editing=true;UpdateButtons();status.Text="正在保存…";
            try{
                var result=await Act(command,path);
                if(!dialog.IsDisposed)status.Text=result?["ok"]?.GetValue<bool>()==true?"已保存。":
                    result?["error"]?.GetValue<string>() is string error?Message(error):"等待系统服务确认。";
            }finally{editing=false;if(!dialog.IsDisposed)Render();}
        }
        paths.SelectedIndexChanged+=(_,_)=>UpdateButtons();
        add.Click+=async(_,_)=>{
            using var picker=new OpenFileDialog{Title="选择要直连的 EXE",Filter="Windows 应用 (*.exe)|*.exe",CheckFileExists=true,DereferenceLinks=false,RestoreDirectory=true};
            if(picker.ShowDialog(dialog)==DialogResult.OK && CanEditDirectApplications)await Change("AddDirectApplication",picker.FileName);
        };
        remove.Click+=async(_,_)=>{if(CanEditDirectApplications && paths.SelectedItem is ListedDirectApplication selected)await Change("RemoveDirectApplication",selected.Path);};
        _updateDirectApplicationDialog=Render;
        try{Render();dialog.ShowDialog(this);}finally{_updateDirectApplicationDialog=null;}
    }
}
