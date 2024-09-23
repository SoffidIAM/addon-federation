package com.soffid.iam.addons.federation.service;

import java.io.IOException;
import java.util.Collection;

import com.soffid.iam.service.VaultService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.comu.Challenge;
import es.caib.seycon.ng.comu.ExecucioPuntEntrada;
import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.PuntEntrada;
import es.caib.seycon.ng.comu.Sessio;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.servei.AccountService;
import es.caib.seycon.ng.servei.AuditoriaService;
import es.caib.seycon.ng.servei.AutoritzacioService;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.DispatcherService;
import es.caib.seycon.ng.servei.DominiUsuariService;
import es.caib.seycon.ng.servei.PuntEntradaService;
import es.caib.seycon.ng.servei.SessioService;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.servei.XarxaService;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.QueryService;
import es.caib.seycon.ng.sync.servei.SecretStoreService;

@Service(serverPath = "/seycon/EssoService")
@Depends({
	FederationService.class,
	QueryService.class,
	SessioService.class,
	UsuariService.class,
	SecretStoreService.class,
	AccountService.class,
	DispatcherService.class,
	DominiUsuariService.class,
	DadesAddicionalsService.class,
	VaultService.class,
	AutoritzacioService.class,
	AuditoriaService.class,
	LogonService.class,
	XarxaService.class,
	PuntEntradaService.class
})
public class EssoService {
    public boolean auditPasswordQuery(String user, String key, @Nullable String account,
    		@Nullable String system, 
    		@Nullable String url,
    		@Nullable String app,
    		@Nullable String sourceIp) {return false;}


    public String doChangeSecret(String sessionKey,
    		String user, 
    		String secret,
    		String account,
    		String system,
    		@Nullable String ssoAttribute, 
    		@Nullable String description, 
    		@Nullable String value) {return null;}
    
    public Sessio createDummySession(String user, String host, 
    		@Nullable String client, @Nullable String port) {return null;}
    
    public Maquina findHostBySerialNumber(String serialNumber) {return null;}
    
    public String[] getHostAdministration(String hostname, String hostIP,
    		String user) { return null;} 
    
    public void setHostAdministration(String hostSerial,
    		String user, Password password) { } 

    public PuntEntrada findApplicationAccessById(@Nullable String user, 
    		Long id) {return null;}
    
    public PuntEntrada findRootAccessTree(@Nullable String user) {return null;}
    
    public Collection<PuntEntrada> findChildren(@Nullable String user, PuntEntrada parent) {return null;}

    public Collection<PuntEntrada> findApplicationAccessByCode(@Nullable String user, 
    		String code) {return null;}
    

    public ExecucioPuntEntrada getExecution (PuntEntrada entryPoint, String remoteIp) {return null;}
    
	public Maquina registerDynamicIP(
			final java.lang.String nomMaquina, 
			final java.lang.String ip, 
			final java.lang.String serialNumber) { return null;}

	public String query(String path, @Nullable String format, @Nullable String ipAddress) { return null;}
	
	public Challenge updateAndRegisterChallenge(@Nullable Challenge challenge, boolean textPush) {return null;}

}
