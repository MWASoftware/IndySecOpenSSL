program delphi_openssl_gui_client;

uses
  Vcl.Forms,
  TestClient in 'TestClient.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
