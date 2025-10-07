unit TestServer;

{$IFDEF FPC}
{$MODE Delphi}
{$ENDIF}

interface

uses
  {$IFDEF FPC}
  Classes, SysUtils,{$IFDEF WINDOWS}Windows, {$ENDIF} StdCtrls, Forms, SyncObjs,
  {$ELSE}
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, System.SyncObjs,
  {$ENDIF}
  IdIOHandler, IdIOHandlerStack, IdSSL, IdSecOpenSSL, IdHTTP, IdComponent,
  IdCustomTCPServer, IdCustomHTTPServer, IdHTTPServer, IdSecOpenSSLX509,
  IdContext, IdGlobal, IdSecOpenSSLSocket,  IdSecOpenSSLAPI, IdIOHandlerSocket,
  IdTCPConnection, IdTCPClient, IdServerIOHandler, IdBaseComponent;

{$IFNDEF FPC}
  const
    WM_DOTEST = WM_USER;
{$ENDIF}

type

  { TForm1 }

  TForm1 = class(TForm)
    Memo1: TMemo;
    Button1: TButton;
    IdHTTPServer1: TIdHTTPServer;
    SSLServerHandler: TIdSecServerIOHandlerSSLOpenSSL;
    IdHTTP1: TIdHTTP;
    SSLClientHandler: TIdSecIOHandlerSocketOpenSSL;
    procedure Button1Click(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure SSLClientHandlerGetPassword(var Password: string);
    procedure SSLClientHandlerStatusInfo(const AMsg: String);
    function SSLClientHandlerVerifyPeer(Certificate: TIdX509;
      AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure IdHTTPServer1QuerySSLPort(APort: TIdPort; var VUseSSL: Boolean);
    procedure IdHTTPServer1CommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    function SSLServerHandlerVerifyPeer(Certificate: TIdX509;
      AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure SSLServerHandlerStatusInfo(const AMsg: string);
  private
    { Private declarations }
    FClosing: boolean;
    FServerMsgQueue: TStrings;
    FServerMsgLock: TCriticalSection;
    procedure CheckServerMsgs;
    procedure Add2LogFromServer(AMsg: String);
    procedure DoTest;
    {$IFDEF FPC}
    procedure OnDoTest(Data: PtrInt);
    {$ELSE}
    procedure OnDoTest(var Msg:TMessage); message WM_DOTEST;
    {$ENDIF}
    procedure ShowCertificate(Certificate : TIdX509);
    procedure ShowServerCertificate(Certificate : TIdX509);
    function CertificateType(Certificate: TIdX509): string;
  public
    { Public declarations }
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

var
  Form1: TForm1;

implementation

{$IFDEF FPC}
{$R *.lfm}
{$ELSE}
{$R *.dfm}
{$ENDIF}

uses IdSecOpenSSLOptions;

const
  myPassword = 'mypassword';
  remoteSource = 'https://localhost:8080/openssltest.txt';
  sGetException = 'Error: Status = %d returned when GETting %s';
  DefaultSSLDirs = '..' + DirectorySeparator + '..' + DirListDelimiter;

  RootCertificatesDir = '..' + DirectorySeparator + 'cacerts';
  CertsDir =  '..' + DirectorySeparator+ 'certs';
  MyRootCertFile = RootCertificatesDir + DirectorySeparator + 'ca.pem';
  MyCertFile = CertsDir + DirectorySeparator+ 'myserver.pem';
  MyKeyFile = CertsDir + DirectorySeparator + 'myserverkey.pem';
  MyClientCertPackage = CertsDir + DirectorySeparator + 'myclient.p12';


type
  TResponseTextBuffer = class(TMemoryStream)
  private
    function GetDataString: AnsiString;
  public
    property DataString: AnsiString read GetDataString;
  end;


procedure TForm1.Button1Click(Sender: TObject);
begin
  Close
end;

function TForm1.CertificateType(Certificate: TIdX509): string;
begin
  if Certificate.Issuer.Hash.C1 = Certificate.Subject.Hash.C1 then
    Result := 'Root'
  else
    Result := 'Remote';
end;

constructor TForm1.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FServerMsgQueue := TStringList.Create;
  FServerMsgLock := TCriticalSection.Create;
end;

destructor TForm1.Destroy;
begin
  if assigned(FServerMsgQueue) then FServerMsgQueue.Free;
  if assigned(FServerMsgLock) then FServerMsgLock.Free;
  inherited Destroy;
end;

procedure TForm1.DoTest;
var ResponseStream: TResponseTextBuffer;
begin
  ResponseStream := TResponseTextBuffer.Create;
  try
    IdHTTP1.Get(remoteSource,ResponseStream);
    CheckServerMsgs;
    if IdHTTP1.ResponseCode = 200 then
    begin
      Memo1.Lines.Add('Remote Source returned:');
      Memo1.Lines.Add(ResponseStream.DataString);
    end
    else
      Memo1.Lines.Add(Format(sGetException,[IdHTTP1.ResponseCode,remoteSource]));
  finally
    ResponseStream.Free;
  end;
  CheckServerMsgs;
  Application.ProcessMessages;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  FClosing := true;
  CanClose := true;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
  Memo1.Lines.Clear;
  {$IFDEF FPC}
  Application.QueueAsyncCall(OnDoTest,0);
  {$ELSE}
  PostMessage(self.Handle,WM_DOTEST,0,0);
  {$ENDIF}
end;

procedure TForm1.IdHTTPServer1CommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var S: TStringStream;
begin
  S := TStringStream.Create('Server Response' + LineEnding);
  S.WriteString('Command: ' + ARequestInfo.RawHTTPCommand + LineEnding);
  S.WriteString('Remote IP: ' + ARequestInfo.RemoteIP + LineEnding);
  S.WriteString('Success!' + LineEnding);
  AResponseInfo.ContentStream := S;
  AResponseInfo.ContentType := 'text/html';
  AResponseInfo.ContentEncoding := 'UTF-8';
  AResponseInfo.CharSet := 'UTF-8';
  AResponseInfo.CloseConnection := true;
  AResponseInfo.ContentStream.Position := 0;
end;

procedure TForm1.IdHTTPServer1QuerySSLPort(APort: TIdPort;
  var VUseSSL: Boolean);
begin
  VUseSSL := (APort = 8080);
end;

procedure TForm1.SSLClientHandlerGetPassword(var Password: string);
begin
  Password := myPassword;
end;

procedure TForm1.SSLClientHandlerStatusInfo(const AMsg: String);
begin
  Memo1.Lines.Add('Client Status Info: '+AMsg);
  CheckServerMsgs;
end;

function TForm1.SSLClientHandlerVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('Client Side Verification');
  if AOK then
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification succeeded')
  else
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification failed');
  ShowCertificate(certificate);
  CheckServerMsgs;
  Result := AOK;
end;

procedure TForm1.SSLServerHandlerStatusInfo(const AMsg: string);
begin
  Add2LogFromServer('Server Status Info: '+AMsg);
end;

procedure TForm1.CheckServerMsgs;
begin
  if FServerMsgQueue <> nil then
  begin
    FServerMsgLock.Enter;
    try
      if FServerMsgQueue.Count > 0 then
        Memo1.Lines.AddStrings(FServerMsgQueue);
      FServerMsgQueue.Clear;
    finally
      FServerMsgLock.Leave;
    end;
  end;
end;

procedure TForm1.Add2LogFromServer(AMsg: String);
begin
  {Use a critical section to sync threads}
  FServerMsgLock.Enter;
  try
    FServerMsgQueue.Add(AMsg);
  finally
    FServerMsgLock.Leave;
  end;
end;

function TForm1.SSLServerHandlerVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Add2LogFromServer('');
  Add2LogFromServer('Server Side Verification');
  if AOK then
   Add2LogFromServer(CertificateType(Certificate)+' Certificate verification succeeded')
  else
   Add2LogFromServer(CertificateType(Certificate)+' Certificate verification failed');
  ShowServerCertificate(certificate);
  Result := AOK;
end;

{$IFDEF FPC}
procedure TForm1.OnDoTest(Data: PtrInt);
{$ELSE}
procedure TForm1.OnDoTest(var Msg:TMessage);
{$ENDIF}
begin
  if GetIOpenSSLDDL <> nil then
    GetIOpenSSLDDL.SetOpenSSLPath(DefaultSSLDirs);

  Memo1.Lines.Add('Using '+OpenSSLVersion);
  if GetIOpenSSLDDL <> nil then
    begin
      Memo1.Lines.Add('LibCrypto: '+GetIOpenSSLDDL.GetLibCryptoFilePath);
      Memo1.Lines.Add('LibSSL: '+GetIOpenSSLDDL.GetLibSSLFilePath);
    end;
  Memo1.Lines.Add('Working Directory = ' + GetCurrentDir);
  with SSLClientHandler do
  begin
    SSLOptions.VerifyDirs := RootCertificatesDir;
    SSLOptions.VerifyDepth := 100;
    SSLOptions.UseSystemRootCertificateStore := false;
  end;
  with SSLServerHandler do
  begin
    SSLOptions.RootCertFile := MyRootCertFile;
    SSLOptions.CertFile := MyCertFile;
    SSLOptions.KeyFile := MyKeyFile;
  end;
  IdHTTPServer1.Active := true;
  Sleep(1000); {let server get going}
  Memo1.Lines.Add('Getting '+remoteSource+' with verification');
  Memo1.Lines.Add('');
  DoTest;
  IdHTTPServer1.Active := false;
  SSLClientHandler.Close;

  {Update SSL Options for client verification}
  with SSLClientHandler do
  begin
    SSLOptions.CertFile := MyClientCertPackage;
    SSLOptions.KeyFile := MyClientCertPackage;
  end;
  with SSLServerHandler do
  begin
    SSLOptions.VerifyMode := [sslvrfPeer,sslvrfFailIfNoPeerCert];
    SSLOptions.VerifyDirs := RootCertificatesDir;
    SSLOptions.VerifyDepth := 100;
    SSLOptions.UseSystemRootCertificateStore := false;
  end;
  IdHTTPServer1.Active := true;
  Sleep(1000); {let server get going}
  Memo1.Lines.Add('Getting '+remoteSource+' with verification and client verification');
  Memo1.Lines.Add('');
  DoTest;
  IdHTTPServer1.Active := false;
  SSLClientHandler.Close;
end;

procedure TForm1.ShowCertificate(Certificate: TIdX509);
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('X.509 Certificate Details (Client)');
  Memo1.Lines.Add('Subject: '+ Certificate.Subject.OneLine);
  Memo1.Lines.Add('Issuer: '+ Certificate.Issuer.OneLine);
  Memo1.Lines.Add('Not Before: '+DateTimeToStr(Certificate.notBefore));
  Memo1.Lines.Add('Not After: '+DateTimeToStr(Certificate.notAfter));
  Memo1.Lines.Add('');
end;

procedure TForm1.ShowServerCertificate(Certificate: TIdX509);
begin
  Add2LogFromServer('');
  Add2LogFromServer('X.509 Certificate Details (Server)');
  Add2LogFromServer('Subject: '+ Certificate.Subject.OneLine);
  Add2LogFromServer('Issuer: '+ Certificate.Issuer.OneLine);
  Add2LogFromServer('Not Before: '+DateTimeToStr(Certificate.notBefore));
  Add2LogFromServer('Not After: '+DateTimeToStr(Certificate.notAfter));
  Add2LogFromServer('');
end;

{ TResponseTextBuffer }

function TResponseTextBuffer.GetDataString: AnsiString;
begin
  SetLength(Result,Size);
  Position := 0;
  Read(Result[1],Size);
  SetCodePage(RawByteString(Result), DefaultSystemCodePage, False);
end;

end.
