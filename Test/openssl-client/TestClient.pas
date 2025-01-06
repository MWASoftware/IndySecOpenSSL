unit TestClient;

{$IFDEF MSWINDOWS}
{$DEFINE WINDOWS}
{$ENDIF}

{$IFDEF CPU386}
{$DEFINE CPU32}
{$ENDIF}

{$IFDEF CPUX64}
{$DEFINE CPU64}
{$ENDIF}

{$IFDEF FPC}
{$mode delphi}
{$codepage utf8}
{$ENDIF}

{$DEFINE HAS_WINDOWS_CERT_STORE}
{$IFDEF UNIX}
{$DEFINE DO_CERT_VERIFICATION}
{$ENDIF}
{$IFDEF HAS_WINDOWS_CERT_STORE}
{$DEFINE DO_CERT_VERIFICATION}
{$ENDIF}

interface

uses
  Classes, SysUtils, {$IFDEF FPC}CustApp,{$ENDIF}IdIOHandler, IdHTTP,
  IdSSL, IdSSLOpenSSL;

const
  remoteSource = 'https://www.mwasoftware.co.uk/openssltest.txt';
  sGetException = 'Error: Status = %d returned when GETting %s';
  rcAccept = 'Application/txt';
  {$if not declared(DirectorySeparator)}
  DirectorySeparator = '\';
  {$ifend}
  {$IFDEF UNIX}
  SSLCertsDirs = '/etc/ssl/certs'      {Debian and friends}
               + ':/etc/pki/tls/certs' {Fedora/RHEL6}
               + ':/etc/ssl'           {OpenSUSE}
               + ':/etc/pki/tks'       {OpenELEC}
               + ':/etc/pki/ca-trust'  {CENTOS/RHEL 7}
               + ':/var/ssl/certs'     {AIX}    ;
  {$ENDIF}


type
   {$if not declared(TCustomApplication)}
   {$DEFINE LOCAL_TCUSTOMAPP}
   TCustomApplication = class(TComponent)
   private
     FTitle: string;
   protected
     procedure DoRun; virtual; abstract;
   public
     function Exename: string;
     procedure Run;
     procedure Terminate;
     property Title: string read FTitle write FTitle;
   end;
   {$IFEND}

  { TBasicHttpsClient }

  TBasicHttpsClient = class(TCustomApplication)
  private
    FSSLHandler: TIdSSLIOHandlerSocketOpenSSL;
    FNoVerification: boolean;
    FVerifyDirs: string;
    FPromptOnExit: boolean;
    FOpenSSLLibDir: string;
    function DoTest: integer;
    function GetSSLHandler(AOwner: TComponent): TIdIOHandler;
    function IsDirectoryEmpty(Path: string): boolean;
    {$IFDEF UNIX}
    function FindOpenSSLCertsDir: string;
    {$ENDIF}
    function CertificateType(Certificate: TIdX509): string;
    function ClientVerifyPeer(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure ShowCertificate(Certificate : TIdX509);
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;

   { TResponseTextBuffer }

   TResponseTextBuffer = class(TMemoryStream)
    private
      function GetDataString: AnsiString;
    public
      property DataString: AnsiString read GetDataString;
    end;


implementation

uses IdSSLOpenSSLAPI;

{$IFDEF LOCAL_TCUSTOMAPP}
function TCustomApplication.Exename: string;
begin
  Result := ParamStr(0);
end;

procedure TCustomApplication.Run;
begin
  try
    DoRun;
  except on E: Exception do
    writeln(E.Message);
  end;
end;

procedure TCustomApplication.Terminate;
begin

end;
{$ENDIF}

{ TResponseTextBuffer }

function TResponseTextBuffer.GetDataString: AnsiString;
begin
  SetLength(Result,Size);
  Position := 0;
  Read(Result[1],Size);
  SetCodePage(RawByteString(Result), DefaultSystemCodePage, False);
end;


{ TBasicHttpsClient }

function TBasicHttpsClient.DoTest: integer;
var httpClient: TIdHttp;
    ResponseStream: TResponseTextBuffer;
begin
  httpClient := TIdHTTP.Create(nil);
  try
    httpClient.HTTPOptions := httpClient.HTTPOptions + [hoNoProtocolErrorException,
                                                        hoKeepOrigProtocol,
                                                        hoWantProtocolErrorContent];
    httpClient.ProtocolVersion := pv1_1;
    httpClient.Request.CustomHeaders.Clear;
    httpClient.Request.Accept := rcAccept;
    httpClient.Request.BasicAuthentication:= false;
    httpClient.HandleRedirects := true;

    httpClient.Request.UserAgent :=' Mozilla/5.0 (compatible; Indy Library)';
    httpClient.Request.ContentType := 'application/x-www-form-urlencoded';
    httpClient.IOHandler := GetSSLHandler(httpClient);

    httpClient.ConnectTimeout := 5000;
    httpClient.ReadTimeout := 20000;
    ResponseStream := TResponseTextBuffer.Create;
    try
      httpClient.Get(remoteSource,ResponseStream);
      {$IFNDEF LEGACYVERSION}
      if assigned (FSSLHandler.SSLSocket) then
        writeln('Using SSL/TLS Version ' + FSSLHandler.SSLSocket.SSLProtocolVersionStr, ' with cipher ',FSSLHandler.SSLSocket.Cipher.Name);
      {$ENDIF}
      Result := httpClient.ResponseCode;
      if Result = 200 then
      begin
        writeln('Remote Source returned:');
        writeln(ResponseStream.DataString);
      end
      else
        writeln(Format(sGetException,[Result,remoteSource]));
    finally
      ResponseStream.Free;
    end;
  finally
    httpClient.Free;
  end;
end;

function TBasicHttpsClient.GetSSLHandler(AOwner: TComponent): TIdIOHandler;
var IOHandler: TIdSSLIOHandlerSocketOpenSSL;
begin
  IOHandler := TIdSSLIOHandlerSocketOpenSSL.Create(AOwner);
  IOHandler.SSLOptions.Mode:= sslmClient;
  {$IFDEF LEGACYVERSION}
  IOHandler.SSLOptions.Method := sslvTLSv1_2;
  {$ENDIF}
  {Linux: VerifyDirs set up to defaults
   Windows: Default cert store copied into OpenSSL X509 store}
  if not FNoVerification then
  begin
    IOHandler.SSLOptions.VerifyMode := [sslvrfPeer, sslvrfFailIfNoPeerCert];
    IOHandler.SSLOptions.VerifyDepth := 100;
    {$IFDEF UNIX}
    if FVerifyDirs <> '' then
    begin
      IOHandler.SSLOptions.VerifyDirs := FVerifyDirs;
      writeln('Using certs from ', IOHandler.SSLOptions.VerifyDirs);
    end;
    {$ENDIF}
  end
  else
    IOHandler.SSLOptions.VerifyMode := [];
  IOHandler.OnVerifyPeer := ClientVerifyPeer;
  FSSLHandler := IOHandler;
  Result := IOHandler;
end;

function TBasicHttpsClient.IsDirectoryEmpty(Path: string): boolean;
var Rslt: TSearchRec;
begin
  Result := true;
  if FindFirst(Path + DirectorySeparator + '*',faNormal or faSymLink,Rslt) = 0 then
  begin
    Result := false;
    FindClose(Rslt);
  end;
end;

{$IFDEF UNIX}
function TBasicHttpsClient.FindOpenSSLCertsDir : string;
var SSLDirs: TStringList;
    i : integer;
begin
  Result := '';
  {$if declared(OpenSSLDir)}
  Result := OpenSSLDir;
  if Result <> '' then
    Result := Result + '/certs';
  {$ifend}
  if (Result = '') or not DirectoryExists(Result) or IsDirectoryEmpty(Result) then
  {See if we can find directory from list of known locations}
  begin
    SSLDirs := TStringList.Create;
    try
      SSLDirs.Delimiter := ':';
      SSLDirs.StrictDelimiter := true;
      SSLDirs.DelimitedText := SSLCertsDirs; {Split list on delimiter}
      for i := 0 to SSLDirs.Count - 1 do
        if DirectoryExists(SSLDirs[i]) and not IsDirectoryEmpty(SSLDirs[i]) then
        begin
          Result := SSLDirs[i];
          break;
        end;
    finally
      SSLDirs.Free;
    end;
  end;
end;
{$ENDIF}

function TBasicHttpsClient.CertificateType(Certificate : TIdX509) : string;
begin
  if Certificate.Issuer.Hash.C1 = Certificate.Subject.Hash.C1 then
    Result := 'Root'
  else
    Result := 'Remote';
end;

function TBasicHttpsClient.ClientVerifyPeer(Certificate : TIdX509;
  AOk : Boolean; ADepth , AError : Integer) : Boolean;
begin
  writeln;
  writeln('Client Side Verification');
  if AOK then
   writeln(CertificateType(Certificate),' Certificate verification succeeded')
  else
   writeln(CertificateType(Certificate),' Certificate verification failed');
  ShowCertificate(certificate);
  Result := AOK;
end;

procedure TBasicHttpsClient.ShowCertificate(Certificate : TIdX509);
begin
  writeln;
  writeln('X.509 Certificate Details');
  writeln('Subject: ', Certificate.Subject.OneLine);
  writeln('Issuer: ', Certificate.Issuer.OneLine);
  writeln('Not Before: ',DateTimeToStr(Certificate.notBefore));
  writeln('Not After: ',DateTimeToStr(Certificate.notAfter));
  writeln;
end;

procedure TBasicHttpsClient.DoRun;

var i: integer;
    FindSSLDir: boolean;

  procedure RunTest;
  var i: integer;
  begin
    {$IFDEF UNIX}
    if FindSSLDir then
      FVerifyDirs := FindOpenSSLCertsDir;
    {$ENDIF}

    writeln('Using ',OpenSSLVersion, ', OpenSSLDir: ', OpenSSLDir);
    if GetIOpenSSLDDL <> nil then
    begin
      writeln('LibCrypto: ',GetIOpenSSLDDL.GetLibCryptoFilePath);
      writeln('LibSSL: ',GetIOpenSSLDDL.GetLibSSLFilePath);
    end;
    if not LoadOpenSSLLibrary then
      raise Exception.Create('OpenSSL Library Failed to load');

    if GetIOpenSSLDDL <> nil then
    with GetIOpenSSLDDL.GetFailedToLoadList do
    if Count > 0 then
    begin
      writeln('Note: The following functions failed to load and an exception will be raised if they are called:');
      for i := 0 to Count - 1 do
        writeln(Strings[i]);
    end;

    writeln('Getting ',remoteSource,' with no verification');
    FNoVerification := true;
    DoTest;
    {$IFDEF DO_CERT_VERIFICATION}
    FNoVerification := false;
    writeln('Getting ',remoteSource,' with verification');
    writeln;
    DoTest;
    {$ENDIF}
end;

begin
  FPromptOnExit := true;
  FindSSLDir := false;
  try
    // quick check parameters
    i := 1;
    while i <= ParamCount do
    begin
      if ParamStr(i) = '-h' then
      begin
        WriteHelp;
        Terminate;
        Exit;
      end;

      if ParamStr(i) = '-n' then
        FPromptOnExit := false
      else
       if (ParamStr(i) = '-l') and (i < ParamCount) then
       begin
         FVerifyDirs := ParamStr(i+1);
         Inc(i);
         if not DirectoryExists(FVerifyDirs) or IsDirectoryEmpty(FVerifyDirs) then
           raise Exception.CreateFmt('%s is not a directory or is empty',[FVerifyDirs]);
       end
       else
       if ParamStr(i) = '-L' then
       {$IFDEF UNIX}
         FindSSLDir := true
       {$ENDIF}
       else
       if DirectoryExists(ParamStr(i)) then
          FOpenSSLLibDir := ParamStr(i)
       else
         raise Exception.CreateFmt('Unrecognised option - %s',[ParamStr(i)]);
       Inc(i);
    end;

    if GetIOpenSSLDDL <> nil then
    begin
      if (FOpenSSLLibDir = '') or not IsDirectoryEmpty(FOpenSSLLibDir) then
      begin
        GetIOpenSSLDDL.SetOpenSSLPath(FOpenSSLLibDir);
        RunTest;
      end
      else
        writeln('Directory ',FOpenSSLLibDir,' is empty!');
    end
    else
      RunTest;


    {$IFDEF WINDOWS}
    if FPromptOnExit then
    begin
      write('Press Return to continue');
      readln; //stop console disappearing until user presses return}
    end;
    {$ENDIF}

  except on E: Exception do
    writeln('Error: ', E.Message);
  end;
  Terminate;
end;

constructor TBasicHttpsClient.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
//  StopOnException:=True;
end;

destructor TBasicHttpsClient.Destroy;
begin
  inherited Destroy;
end;

procedure TBasicHttpsClient.WriteHelp;
begin
  { add your help code here }
  writeln('Basic Https Client');
  writeln('Gets text file from ' + remoteSource + ' and prints it');
  writeln('Usage: ', ExtractFileName(ExeName), ' [-h] [-n] [-l <cacerts dir>] [-L] [OpenSSL lib dir]')
end;


end.

