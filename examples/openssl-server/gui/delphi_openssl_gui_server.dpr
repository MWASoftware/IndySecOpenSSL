program delphi_openssl_gui_server;

uses
  Vcl.Forms,
  TestServer in 'TestServer.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
