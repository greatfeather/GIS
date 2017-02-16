package com.supermap.services.security;


import com.supermap.server.config.ComponentSetting;
import com.supermap.server.config.ComponentSettingSet;
import com.supermap.server.config.ProviderSetting;
import com.supermap.server.config.ProviderSettingSet;
import com.supermap.server.config.SQLSecurityInfoStorageSetting;
import com.supermap.server.config.SecurityInfoStorageSetting;
import com.supermap.server.config.SecuritySetting;
import com.supermap.server.config.ServerConfiguration;
import com.supermap.server.config.SessionSetting;
import com.supermap.services.components.commontypes.AuthorizeSetting;
import com.supermap.services.event.SimpleEventHelper;
import com.supermap.services.providers.InvalidLicenseException;
import com.supermap.services.providers.LicenseChecker;
import com.supermap.services.rest.resources.SecurityManageResource;
import com.supermap.services.security.storages.ConnectionException;
import com.supermap.services.security.storages.DefaultStorageFactory;
import com.supermap.services.security.storages.MySQlStorage;
import com.supermap.services.security.storages.Storage;
import com.supermap.services.security.storages.StorageFactory;
import com.supermap.services.security.storages.StorageSettingValidException;
import com.supermap.services.security.storages.StorageStateObserver;
import com.supermap.services.security.storages.StorageStatusListener;
import com.supermap.services.security.storages.SwitchException;
import com.supermap.services.util.LogUtil;
import com.supermap.services.util.ResourceManager;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordService;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.ini4j.Ini;
import org.ini4j.InvalidFileFormatException;
import org.ini4j.Profile;
import org.ini4j.Profile.Section;
import org.slf4j.cal10n.LocLogger;

public class ManagerEx
  implements UsernamePasswordRealmListener, StorageStatusListener
{
  private static final ResourceManager b = new ResourceManager("resource.securityManageResources");
  private static final LocLogger c = LogUtil.getLocLogger(ManagerEx.class, b);
  private static volatile ManagerEx d;
  ServerConfiguration a;
  private Map<String, User> e;
  private Map<String, UserGroup> f;
  private Map<String, Role> g;
  private List<SecurityEnabledListener> h = new ArrayList();
  private CreateAdminUserListener i = (CreateAdminUserListener)SimpleEventHelper.createDelegate(CreateAdminUserListener.class);
  private Ini j;
  private PasswordService k = new DefaultPasswordService();
  private boolean l;
  private ReentrantReadWriteLock m = new ReentrantReadWriteLock();
  private Lock n = this.m.readLock();
  private Lock o = this.m.writeLock();
  private CasConfigUtils p;
  private int q = 0;
  private SecurityInfoDAO r;
  private List<Role> s;
  private File t;
  private ServiceBeanPermissionDAO u;
  private UsernamePasswordRealmListener v;
  private SecuritySetting w;
  private StorageFactory x = new DefaultStorageFactory();
  private SessionManagerFactory y = new DefaultSessionManagerFactory();
  private Storage z;
  private DefaultWebSecurityManager A;

  public ManagerEx()
  {
  }

  public ManagerEx(File shiroFile, SecuritySetting setting, DefaultWebSecurityManager securityManager)
  {
    this();
    this.t = shiroFile;
    this.w = setting;
    this.A = securityManager;
  }

  public static void setInstance(ManagerEx manager) {
    d = manager;
  }

  public static ManagerEx getInstance() {
    return d;
  }

  public File getIniFile() {
    return this.t;
  }

  public void setIniFile(File iniFile) {
    this.t = iniFile;
  }

  public SecuritySetting getSetting() {
    return this.w;
  }

  public void setSetting(SecuritySetting setting) {
    this.w = setting;
  }

  private static void a(Role paramRole, RolePermissions paramRolePermissions)
  {
    paramRole.permissions = paramRolePermissions;
  }

  private static boolean a(User paramUser)
  {
    String[] arrayOfString1 = paramUser.roles;
    if ((arrayOfString1 == null) || (arrayOfString1.length <= 0)) {
      return false;
    }
    for (String str : arrayOfString1) {
      if (str.equals("PORTAL_USER")) {
        return true;
      }
    }
    return false;
  }

  private static User b(User paramUser) {
    User localUser = paramUser.copy();
    if ((!StringUtils.equals(paramUser.name, "GUEST")) && (!ArrayUtils.contains(paramUser.roles, "USER"))) {
      localUser.roles = ((String[])ArrayUtils.add(paramUser.roles, "USER"));
    }
    return localUser;
  }

  private static void a(User paramUser1, User paramUser2)
  {
    if (paramUser1.isRole("SYSTEM")) {
      if (paramUser2 == null) {
        //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKSYSTEMUSER_REMOVE_SYSTEMUSER, new Object[] { paramUser1.name }));
      }
      if ((StringUtils.equals(paramUser1.name, paramUser2.name)) && (Arrays.equals(paramUser1.roles, paramUser2.roles))) {
        return;
      }
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKSYSTEMUSER_ALTER_SYSTEMUSER, new Object[] { paramUser1.name }));
    }
  }

  private static void b(String paramString) {
    if (("ADMIN".equals(paramString)) || ("PUBLISHER".equals(paramString)) || ("PORTAL_USER".equals(paramString)) || 
      ("USER"
      .equals(paramString)))
    {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_REMOVE_ROLE_ASSERTNOT_DEFAULT, new Object[] { paramString }));
    }
  }

  private static Ini a(File paramFile) {
    Ini localIni = null;
    try {
      localIni = new Ini();

      localIni.getConfig().setComment(false);
      localIni.setFile(paramFile);
      localIni.load();
    } catch (InvalidFileFormatException localInvalidFileFormatException) {
      //c.warn(b.getMessage(SecurityManageResource.MANAGER_LOADINI_SHIRO_CONFIGFILE_FORMATEXCEPTION, new Object[] { paramFile.getAbsolutePath(), localInvalidFileFormatException
     //   .getMessage() }));
      //c.debug(localInvalidFileFormatException.getMessage(), localInvalidFileFormatException);
    } catch (IOException localIOException) {
     // c.warn(b.getMessage(SecurityManageResource.MANAGER_LOADINI_SHIRO_CONFIGFILE_IOEXCEPTION, new Object[] { paramFile
      //  .getAbsolutePath(), localIOException.getMessage() }));
     // c.debug(localIOException.getMessage(), localIOException);
    }
    return localIni;
  }

  private static void a(Object paramObject, String paramString) {
    if (paramObject == null)
    ;// throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_ASSERTNOTNULL_PARAM_NULL, new Object[] { paramString }));
  }

  public void dispose()
  {
    if (this.r != null) {
      this.r.dispose();
    }
    if (this.u != null)
      this.u.dispose();
  }

  public void resetAdminUser(User user)
  {
    User localUser1 = getSystemUser();
    try {
      this.o.lock();
      User localUser2 = b(user);
      if (localUser1 == null)
        a(localUser2, null, null);
      else {
        this.r.alterUser(localUser1.name, localUser2);
      }

      reloadSecurityInfoFromDAO();
    } finally {
      this.o.unlock();
    }
  }

  public SecurityInfoDAO getSecurityInfoDAO() {
    return this.r;
  }

  public void setSecurityInfoDAO(SecurityInfoDAO value) {
    this.r = value;
  }

  public void setBeanPermissionDAO(ServiceBeanPermissionDAO value) {
    this.u = value;
  }

  public void setServerConfiguration(ServerConfiguration serverConfiguration) {
    this.a = serverConfiguration;
  }

  public void reload(boolean reloadStorage) throws ConnectionException {
    Ini localIni = a(this.t);
    this.j = localIni;
    this.p = new CasConfigUtils();
    if (reloadStorage) {
      reloadStorage();
    }
    reloadSecurityInfoFromDAO();
    this.l = g();
    this.q = e();
    resetSessionSetting(this.w.sessionSetting);
    f();
  }

  public void reload() throws ConnectionException {
    reload(true);
  }

  public void reloadStorage() throws ConnectionException {
    if (this.z != null) {
      this.z.dispose();
    }
    this.z = a();
    this.r.setStorage(this.z);
    this.u.setStorage(this.z);
  }

  public void resetSessionSetting(SessionSetting setting) throws ConnectionException {
    SessionManager localSessionManager = this.y.newInstance(setting);
    if (localSessionManager != null) {
      this.A.setSessionManager(localSessionManager);
      this.w.sessionSetting = setting;
    } else {
      throw new IllegalArgumentException("sesionManager null");
    }
  }

  private Storage a() throws ConnectionException {
    try {
      Storage localStorage = a(this.w.storageSetting);
      addStorageListener(localStorage);
      return localStorage; } catch (StorageSettingValidException localStorageSettingValidException) {
    }
    return null;
  }

  public void addStorageListener(Storage storage)
  {
    if ((storage instanceof StorageStateObserver)) {
      ((StorageStateObserver)storage).addStorageListener(this);
      ((MySQlStorage)storage).executionMonitor();
    }
  }

  public void resetStorageSetting(SecurityInfoStorageSetting storageSetting) throws StorageSettingValidException, ConnectionException, SwitchException {
    if (storageSetting == null) {
      throw new IllegalArgumentException("setting null");
    }
    if (storageSetting.equals(getSetting().storageSetting)) {
      return;
    }
    Storage localStorage1 = a(storageSetting);
    addStorageListener(localStorage1);
    Storage localStorage2 = null;
    try {
      localStorage2 = this.r.getStorage();
      User localUser = d.getSystemUser();
      this.r.setStorage(localStorage1);
      this.u.setStorage(localStorage1);
      reloadSecurityInfoFromDAO();
      a(storageSetting, localUser);
      this.w.storageSetting = storageSetting;
    } finally {
      if (localStorage2 != null)
        localStorage2.dispose();
    }
  }

  private void a(SecurityInfoStorageSetting paramSecurityInfoStorageSetting, User paramUser) throws SwitchException
  {
    try {
      if ((paramSecurityInfoStorageSetting instanceof SQLSecurityInfoStorageSetting)) {
        if (!((SQLSecurityInfoStorageSetting)paramSecurityInfoStorageSetting).isUseStoredAdmin())
          d.resetAdminUser(paramUser);
      }
      else
        d.resetAdminUser(paramUser);
    }
    catch (Exception localException) {
      //String str = b.getMessage(SecurityManageResource.DATABASE_IS_LOCKED, new Object[0]);
      //throw new SwitchException(str, localException);
    }
  }

  public void rollBackStorage(SecurityInfoStorageSetting storageSetting) {
    Storage localStorage1 = null;
    try {
      Storage localStorage2 = a(storageSetting);
      localStorage1 = this.r.getStorage();
      if (localStorage1 != null) {
        this.r.setStorage(localStorage2);
        this.u.setStorage(localStorage2);
        reloadSecurityInfoFromDAO();
      }
    } catch (Exception localException1) {
      throw new IllegalArgumentException("rollBack Storage Exception");
    } finally {
      if (localStorage1 != null)
        localStorage1.dispose();
    }
  }

  private Storage a(SecurityInfoStorageSetting paramSecurityInfoStorageSetting) throws StorageSettingValidException, ConnectionException
  {
    return this.x.newInstance(paramSecurityInfoStorageSetting);
  }

  public void reloadSecurityInfoFromDAO()
  {
    d();
    c();
    b();
  }

  private void b() {
    this.f = a(this.r.getGroups(0, 0).records);
  }

  private void c() {
    this.e = a(this.r.getUsers(0, 0).records);
  }

  private void d() {
    Collection localCollection = this.r.getRoles(0, 0).records;
    String[] arrayOfString = new String[localCollection.size()];
    int i1 = -1;
    for (Object localObject1 = localCollection.iterator(); ((Iterator)localObject1).hasNext(); ) {Role localObject2 = (Role)((Iterator)localObject1).next();
      i1++; arrayOfString[i1] = ((Role)localObject2).name;
    }
    Map<String, RolePermissions> localObject1 = this.u.getRolePermissions(arrayOfString);

    for (Object localObject2 = localCollection.iterator(); ((Iterator)localObject2).hasNext(); ) { Role localRole = (Role)((Iterator)localObject2).next();
      RolePermissions localRolePermissions = (RolePermissions)((Map)localObject1).get(localRole.name);
      if (localRolePermissions == null) {
        localRolePermissions = new RolePermissions();
        localRolePermissions.componentManagerPermissions = new MixedPermissions();
        localRolePermissions.instanceAccessPermissions = new MixedPermissions();
      }
      a(localRole, localRolePermissions);
    }

    this.g = a(localCollection);
    this.s = new ArrayList(this.g.values());
    this.s.remove(this.g.get("SYSTEM"));
  }

  private <T extends Named> Map<String, T> a(Collection<T> paramCollection)
  {
    HashMap localHashMap = new HashMap();
    for (Named localNamed : paramCollection) {
      localHashMap.put(localNamed.name, localNamed);
    }
    localHashMap.remove("EVERYONE");
    localHashMap.remove("SYSTEM_INTERFACE_VIEW");
    return localHashMap;
  }

  public List<String> listUsers() {
    try {
      this.n.lock();
      ArrayList localArrayList = new ArrayList(this.e.keySet());
      return localArrayList;
    } finally {
      this.n.unlock(); 
    }
    //throw localObject;
  }

  public List<User> getAllUsers()
  {
    try {
      this.n.lock();
      c();
      ArrayList localArrayList = new ArrayList(this.e.values());
      return localArrayList;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public User getUser(String name)
  {
    a(name, "userName");
    try {
      this.n.lock();
      User localUser1 = (User)this.e.get(name);
      User localUser2 = localUser1 == null ? null : localUser1.copy();
      return localUser2;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  private int e()
  {
    int i1 = 0;
    List<String> localList = listUsers();
    for (String str : localList) {
      User localUser = getUser(str);
      if (a(localUser)) {
        i1++;
      }
    }
    return i1;
  }

  public void addUser(User user) {
    addUser(user, null, null);
  }

  public void addLdapUser(User user) {
    if (StringUtils.isNotBlank(user.password)) {
      user.password = this.k.encryptPassword(user.password);
    }
    a(user, null, null);
  }

  public void unlockUser(String name) {
    this.r.unlockUser(name);
    c();
  }

  public void addUser(User user, String openID, String loginType) {
    d(user);
    if (!user.password.matches("^.{4,18}$")) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSER_USER_PASSWORD_FORMAT_ERROR, new Object[0]));
    }
    user.password = this.k.encryptPassword(user.password);
    a(user, openID, loginType);
  }

  private void a(User paramUser, String paramString1, String paramString2)
  {
    boolean bool = a(paramUser);
    if ((bool) && (this.q + 1 > LicenseChecker.getIPortalLicUserCount()))
      //throw new InvalidLicenseException(b.getMessage(SecurityManageResource.MANAGER_IPORTAL_USERCOUNT_LIC_ERROR, new Object[0]));
    try
    {
      this.o.lock();
      User localUser1 = getUser(paramUser.name);
      if (localUser1 != null) {
        //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USER_EXISTS, new Object[] { paramUser.name }));
      }
      if ((ArrayUtils.contains(paramUser.roles, "SYSTEM")) && (!ArrayUtils.isEmpty(getRole("SYSTEM").users))) {
        //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_SYSTEM_USER_EXISTS, new Object[0]));
      }
      User localUser2 = b(paramUser);
      if ((StringUtils.isNotBlank(paramString1)) && (paramString2 != null))
        this.r.addOAuthUser(paramString1, paramString2, localUser2);
      else {
        this.r.addUser(localUser2);
      }

      if (bool) {
        this.q += 1;
      }
      reloadSecurityInfoFromDAO();
    } finally {
      this.o.unlock();
    }
  }

  public void removeUser(String name) {
    a(name, "userName");
    User localUser = getUser(name);
    if (localUser == null) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USER_NOT_EXISTS, new Object[] { name }));
    }
    //a(localUser, null);
    c(localUser);
  }

  private void c(User paramUser) {
    try {
      this.o.lock();
      this.r.removeUsers(new String[] { paramUser.name });
      this.e.remove(paramUser.name);
      if ((a(paramUser)) && (this.q > 0)) {
        this.q -= 1;
      }
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock(); }
  }

  public void alterLdapUser(User user)
  {
    a(user, "user");
    String str = user.name;
    User localUser = getUser(str);
    if (localUser == null) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USER_NOT_EXISTS, new Object[] { str }));
    }
    if (StringUtils.isNotBlank(user.password)) {
      user.password = this.k.encryptPassword(user.password);
    }
    a(str, user, localUser);
  }

  public void alterUser(String name, User user) {
    d(user);
    String str = user.password;
    User localUser = getUser(name);
    if (localUser == null) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USER_NOT_EXISTS, new Object[] { name }));
    }
    if ((!ArrayUtils.contains(localUser.roles, "SYSTEM")) && (user.roles != null) && 
      (ArrayUtils.contains(user.roles, "SYSTEM")))
    {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSER_ALTERUSER_ROLEHASSYSTEM, new Object[0]));
    }
    if (StringUtils.isEmpty(user.password)) {
      user.password = localUser.password;
    } else if (!StringUtils.equals(user.password, localUser.password)) {
      a(user.password);
      user.password = this.k.encryptPassword(user.password);
    }
    this.r.isSameAsFormPassword(user.name, str);
    a(name, user, localUser);
  }

  void a(String paramString) {
    Pattern localPattern1 = Pattern.compile("\\S*[A-Za-z]+\\S*");
    Pattern localPattern2 = Pattern.compile("\\S*[0-9]+\\S*");
    Pattern localPattern3 = Pattern.compile("\\S*[\\W_]+\\S*");

    Pattern localPattern4 = Pattern.compile("\\S{6,18}");

    boolean bool1 = localPattern1.matcher(paramString).matches();
    boolean bool2 = localPattern2.matcher(paramString).matches();
    boolean bool3 = localPattern3.matcher(paramString).matches();
    boolean bool4 = localPattern4.matcher(paramString).matches();

    if ((!bool1) || (!bool2) || (!bool3) || (!bool4))
     ;// throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSER_USER_PASSWORD_FORMAT_ERROR, new Object[0]));
  }

  private void a(String paramString, User paramUser1, User paramUser2)
  {
    try {
      this.o.lock();
      if ((a(paramUser1)) && (!a(paramUser2)) && (this.q + 1 > LicenseChecker.getIPortalLicUserCount())) {
       // throw new InvalidLicenseException(b.getMessage(SecurityManageResource.MANAGER_IPORTAL_USERCOUNT_LIC_ERROR, new Object[0]));
      }
      a(paramUser2, paramUser1);
      User localUser = b(paramUser1);
      this.r.alterUser(paramString, localUser);
      reloadSecurityInfoFromDAO();
    } finally {
      this.o.unlock();
    }
  }

  public void alterUserPassword(String userName, String newPassword, String originPassword) {
    a(userName, "userName");
    a(newPassword, "newPassword");
    User localUser1 = getUser(userName);
    if (localUser1 == null) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USER_NOT_EXISTS, new Object[] { userName }));
    }
    if (!this.k.passwordsMatch(originPassword, localUser1.password)) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_ALTERUSERPASSWORD_ILLEGALARGUMENTEXCEPTION, new Object[0]));
    }
    User localUser2 = localUser1.copy();
    localUser2.password = newPassword;
    alterUser(userName, localUser2);
  }

  public List<String> listRoles()
  {
    try
    {
      this.n.lock();
      ArrayList localArrayList = new ArrayList();
      for (Object localObject1 = this.s.iterator(); ((Iterator)localObject1).hasNext(); ) { Role localRole = (Role)((Iterator)localObject1).next();
        localArrayList.add(localRole.name);
      }
      ArrayList localObject1 = localArrayList;
      return localObject1;
    } finally {
      this.n.unlock(); } //throw localObject2;
  }

  public List<Role> getAllRoles()
  {
    try
    {
      this.n.lock();
      ArrayList localArrayList = new ArrayList(this.s);
      return localArrayList;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public Role getRole(String name)
  {
    try {
      this.n.lock();
      Role localRole1 = (Role)this.g.get(name);
      Role localRole2 = localRole1 == null ? null : localRole1.copy();
      return localRole2;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public void addRole(Role role)
  {
    b(role);
    try {
      this.o.lock();
      Role localRole = getRole(role.name);
      if (localRole != null) {
       // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_ROLE_EXISTS, new Object[] { role.name }));
      }
      this.r.addRole(role);
      a(role);
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock(); }
  }

  private void a(Role paramRole)
  {
    LinkedList localLinkedList = new LinkedList();
    if (paramRole.permissions != null) {
      if (paramRole.permissions.componentManagerPermissions != null) {
        Set<String> localSet = this.u.getPermission(null, null, 
          Arrays.asList(new String[] { "SYSTEM_INTERFACE_VIEW" }), 
          null);
        HashSet localHashSet = new HashSet(localSet.size());
        String str1 = "interface:view:interface^";
        for (String str2 : localSet) {
          if (StringUtils.startsWith(str2, str1)) {
            localHashSet.add(str2.substring(str1.length()));
          }
        }
        a(localLinkedList, paramRole.name, paramRole.permissions.componentManagerPermissions.permitted, true, localHashSet);

        a(localLinkedList, paramRole.name, paramRole.permissions.componentManagerPermissions.denied, false, localHashSet);
      }

      this.u.setRolePermissions(paramRole.name, paramRole.permissions, (ServiceBeanPermission[])localLinkedList.toArray(new ServiceBeanPermission[localLinkedList.size()]));
    }
  }

  private void a(List<ServiceBeanPermission> paramList, String paramString, String[] paramArrayOfString, boolean paramBoolean, Set<String> paramSet)
  {
    if (ArrayUtils.isEmpty(paramArrayOfString)) {
      return;
    }
    for (String str : paramArrayOfString) {
      ComponentSetting localComponentSetting = this.a.getComponentSetting(str);
      if (localComponentSetting == null) {
        ComponentSettingSet localComponentSettingSet = this.a.getComponentSettingSet(str);
        if (localComponentSettingSet == null) {
          continue;
        }
        a(paramList, paramString, localComponentSettingSet, paramBoolean, paramSet);
      } else {
        a(paramList, paramString, localComponentSetting, paramBoolean, paramSet);
      }
    }
  }

  private void a(List<ServiceBeanPermission> paramList, String paramString, ComponentSettingSet paramComponentSettingSet, boolean paramBoolean, Set<String> paramSet)
  {
    paramList.add(paramBoolean ? new ServiceBeanPermission().role(paramString).allowComponentSet(paramComponentSettingSet.name) : new ServiceBeanPermission().role(paramString)
      .denyComponentSet(paramComponentSettingSet.name));

    if (paramComponentSettingSet.settings == null) {
      return;
    }
    for (ComponentSetting localComponentSetting : paramComponentSettingSet.settings)
      a(paramList, paramString, localComponentSetting, paramBoolean, paramSet);
  }

  private void a(List<ServiceBeanPermission> paramList, String paramString, ComponentSetting paramComponentSetting, boolean paramBoolean, Set<String> paramSet)
  {
    paramList.add(paramBoolean ? new ServiceBeanPermission().role(paramString).allowComponent(paramComponentSetting.name) : new ServiceBeanPermission().role(paramString)
      .denyComponent(paramComponentSetting.name));

    String[] arrayOfString1 = StringUtils.split(paramComponentSetting.interfaceNames, ',');
    Subject localSubject = ThreadContext.getSubject();
    Object localObject;
    if (!ArrayUtils.isEmpty(arrayOfString1))
    {
      String str;
      if (localSubject == null)
    	for(int i=0;i<arrayOfString1.length;i++){
        //for (str : arrayOfString1) {
    	  str = arrayOfString1[i];
          localObject = new ServiceBeanPermission().role(paramString);
          paramList.add(paramBoolean ? ((ServiceBeanPermission)localObject).allowInterface(str) : ((ServiceBeanPermission)localObject).denyInterface(str));
        }
      else {
    	  for(int i=0;i<arrayOfString1.length;i++){
    	        //for (str : arrayOfString1) {
    	    	  str = arrayOfString1[i];
          if (paramSet.contains(str)) {
            continue;
          }
          localObject = new ServiceBeanPermission().role(paramString);
          paramList.add(paramBoolean ? ((ServiceBeanPermission)localObject).allowInterface(str) : ((ServiceBeanPermission)localObject).denyInterface(str));
        }
      }
    }
    Object[] arrPrividers = StringUtils.split(paramComponentSetting.providers);
    if (!ArrayUtils.isEmpty(arrPrividers))
      for(int i=0;i<arrPrividers.length;i++){
      //for (localObject : arrPrividers) {
    	  localObject = arrPrividers[i];
        ProviderSettingSet localProviderSettingSet = this.a.getProviderSettingSet((String)localObject);
        ServiceBeanPermission localServiceBeanPermission;
        if (localProviderSettingSet != null) {
          localServiceBeanPermission = new ServiceBeanPermission().role(paramString);
          paramList.add(paramBoolean ? new ServiceBeanPermission().allowProviderSet((String)localObject) : localServiceBeanPermission
            .denyProviderSet((String)localObject));

          if (localProviderSettingSet.settings != null)
            for (ProviderSetting localProviderSetting : localProviderSettingSet.settings) {
              localServiceBeanPermission = new ServiceBeanPermission().role(paramString);
              paramList.add(paramBoolean ? localServiceBeanPermission.allowProvider(localProviderSetting.name) : localServiceBeanPermission.denyProvider(localProviderSetting.name));
            }
        }
        else if (this.a.getProviderSetting((String)localObject) != null) {
          paramList.add(paramBoolean ? new ServiceBeanPermission().role(paramString).allowProvider((String)localObject) : new ServiceBeanPermission()
            .role(paramString)
            .denyProvider((String)localObject));
        }
      }
  }

  public void removeRole(String name)
  {
    a(name, "roleName");
    b(name);
    Role localRole = getRole(name);
    if (localRole == null)
     // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_ROLE_NOT_EXISTS, new Object[] { name }));
    try
    {
      this.o.lock();
      this.r.removeRoles(new String[] { name });
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock(); }
  }

  public void alterRole(String name, Role role)
  {
    b(role);
    a(name, role.users);
    try {
      this.o.lock();
      Role localRole = getRole(name);
      if (localRole == null) {
       // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_ROLE_NOT_EXISTS, new Object[] { name }));
      }
      this.r.alterRole(name, role);
      a(role);
      reloadSecurityInfoFromDAO();
    } finally {
      this.o.unlock();
    }
  }

  private void a(String paramString, String[] paramArrayOfString)
  {
    int i1 = 0;
    if ((paramArrayOfString != null) && (paramArrayOfString.length > 0)) {
      for (int i2 = 0; i2 < paramArrayOfString.length; i2++) {
        if (StringUtils.isEmpty(paramArrayOfString[i2])) {
          continue;
        }
        User localUser = getUser(paramArrayOfString[i2]);
        if (localUser.isRole("SYSTEM")) {
          i1 = 1;
        }
      }
    }
    if ((("ADMIN".equalsIgnoreCase(paramString)) && (i1 == 0)) || ((!"ADMIN".equalsIgnoreCase(paramString)) && (i1 != 0)))
     ;// throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSERROLE_ALTERROLE_SYSTEMUSER, new Object[0]));
  }

  public List<String> listUrlRules()
  {
    throw new UnsupportedOperationException();
  }

  public UrlRule getUrlRule(String id)
  {
    throw new UnsupportedOperationException();
  }

  public void addUrlRule(UrlRule urlRule)
  {
    throw new UnsupportedOperationException();
  }

  public void removeUrlRule(String id)
  {
    throw new UnsupportedOperationException();
  }

  public void alterUrlRule(String id, UrlRule urlRule)
  {
    throw new UnsupportedOperationException();
  }

  public boolean isSecurityEnabled()
  {
    return this.l;
  }

  public void setSecurityEnabled(boolean enabled) {
    try {
      this.o.lock();
      this.l = enabled;
      Profile.Section localSection = h();
      localSection.put("config", Config.class.getCanonicalName());
      localSection.put("config.enabled", Boolean.valueOf(enabled));
      f();
      for (SecurityEnabledListener localSecurityEnabledListener : this.h) {
        if (localSecurityEnabledListener != null) {
          try {
            localSecurityEnabledListener.onEnabledModified(enabled);
          } catch (Exception localException) {
           // c.debug(localException.getMessage(), localException);
          }continue;
        }
      }
    }
    finally
    {
      this.o.unlock();
    }
  }

  public void refreshSecurityEnabled()
  {
    if (this.t != null) {
      Ini localIni = a(this.t);
      this.j = localIni;
      this.l = g();

      for (SecurityEnabledListener localSecurityEnabledListener : this.h)
        if (localSecurityEnabledListener != null) {
          try {
            localSecurityEnabledListener.onEnabledModified(this.l);
          } catch (Exception localException) {
           // c.debug(localException.getMessage(), localException);
          }continue;
        }
    }
  }

  public void addSecurityEnabledListener(SecurityEnabledListener listener)
  {
    a(listener, "listener");
    try {
      this.n.lock();
      this.h.add(listener);

      this.n.unlock(); } finally { this.n.unlock(); }
  }

  public void removeSecurityEnabledListener(SecurityEnabledListener listener)
  {
    a(listener, "listener");
    try {
      this.n.lock();
      this.h.remove(listener);

      this.n.unlock(); } finally { this.n.unlock();
    }
  }

  public boolean isAdminExistsOrNot()
  {
    return getSystemUser() != null;
  }

  public User getSystemUser() {
    try {
      this.n.lock();
      Collection<User> localCollection = this.e.values();
      for (User localUser1 : localCollection) {
        if (localUser1.roles == null) {
          continue;
        }
        if ((ArrayUtils.contains(localUser1.roles, "SYSTEM")) || (ArrayUtils.contains(localUser1.roles, "SYSTEM".toLowerCase()))) {
          User localUser2 = localUser1;
          return localUser2;
        }
      }
      return null;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public void addAdminUser(String userName, String password)
  {
    try
    {
      User localUser = new User();
      localUser.name = userName;
      localUser.password = password;
      localUser.roles = new String[] { "ADMIN", "SYSTEM" };
      addUser(localUser);
    } finally {
      this.i.adminUserCreated();
    }
  }

  public void addCreateAdminUserListener(CreateAdminUserListener listener) {
    SimpleEventHelper.addListener(this.i, listener);
  }

  private void f() {
    try {
      this.j.store();
    } catch (IOException localIOException) {
      //c.warn(b.getMessage(SecurityManageResource.MANAGER_STOREINI_IOEXCEPTION, new Object[0]), localIOException);
    }
  }

  private void d(User paramUser) {
    a(paramUser, "user");
    if (paramUser.name == null) {
     // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSER_USER_NAME_NULL, new Object[0]));
    }
    if (paramUser.password == null)
     ;// throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKUSER_USER_PASSWORD_NULL, new Object[0]));
  }

  private void b(Role paramRole)
  {
    a(paramRole, "role");
    if (paramRole.name == null) {
      //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKROLE_ROLE_NAME_NULL, new Object[0]));
    }
    if ("SYSTEM".equals(paramRole.name))
      ;//throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKROLE_ROLE_NOT_SYSTEM, new Object[0]));
  }

  public String generateUUID()
  {
    return UUID.randomUUID().toString();
  }

  private boolean g() {
    Profile.Section localSection = h();
    String str = (String)localSection.get("config.enabled");
    return "true".equalsIgnoreCase(str);
  }

  private String a(String paramString1, String paramString2) {
    Profile.Section localSection = h();
    String str = (String)localSection.get(paramString1);
    if (StringUtils.isBlank(str)) {
      str = paramString2;
    }
    return str;
  }

  private Profile.Section h() {
    Profile.Section localSection = (Profile.Section)this.j.get("main");
    if (localSection == null) {
      localSection = this.j.add("main");
    }
    return localSection;
  }

  @Deprecated
  public List<String> listRolesByInstance(String instanceName)
  {
    return Collections.emptyList();
  }

  public List<String> listRolesByNotInstance(String instanceName)
  {
    ArrayList localArrayList = new ArrayList();
    Collection<Role> localCollection = this.g.values();
    for (Role localRole : localCollection) {
      if (!localRole.name.equals("ADMIN")) {
        localArrayList.add(localRole.name);
      }
    }
    return localArrayList;
  }

  public void updateInstanceAuthorisation(String name, AuthorizeSetting authorizeSetting) {
    this.o.lock();
    try {
      String[] arrayOfString1 = (String[])ArrayUtils.addAll(authorizeSetting.deniedRoles, authorizeSetting.permittedRoles);
      AuthorizeSetting localAuthorizeSetting = null;
      if (ArrayUtils.isEmpty(arrayOfString1)) {
        localAuthorizeSetting = authorizeSetting;
      } else {
        boolean[] arrayOfBoolean = this.r.isRolesExist(arrayOfString1);
        HashSet localHashSet = new HashSet(arrayOfString1.length);
        for (int i1 = 0; i1 < arrayOfBoolean.length; i1++) {
          if (arrayOfBoolean[i1] == true) {
            localHashSet.add(arrayOfString1[i1]);
          }
        }
        String[] arrayOfString2 = (String[])localHashSet.toArray(new String[localHashSet.size()]);
        localAuthorizeSetting = new AuthorizeSetting(authorizeSetting);
        localAuthorizeSetting.deniedRoles = ((String[])ArrayUtils.removeElements(localAuthorizeSetting.deniedRoles, arrayOfString2));
        localAuthorizeSetting.permittedRoles = ((String[])ArrayUtils.removeElements(localAuthorizeSetting.permittedRoles, arrayOfString2));
      }
      this.u.updateInstanceAuthorisation(name, localAuthorizeSetting);
      d();
    } finally {
      this.o.unlock();
    }
  }

  public void deleteInstanceAuthorisation(String[] names) {
    String[] arrayOfString = new String[names.length];
    for (int i1 = 0; i1 < arrayOfString.length; i1++)
      arrayOfString[i1] = ("instance^" + names[i1]);
    try
    {
      this.o.lock();
      this.u.removeInstances(names);
      d();
    } finally {
      this.o.unlock();
    }
  }

  public Map<String, AuthorizeSetting> getInstanceAuthorisations(String[] instanceNames) {
    if (ArrayUtils.isEmpty(instanceNames)) {
      return Collections.emptyMap();
    }
    Map localMap = this.u.getInstanceAuthorisations();
    HashSet<String> localHashSet = new HashSet(localMap.keySet());
    localHashSet.removeAll(Arrays.asList(instanceNames));
    for (String str : localHashSet) {
      localMap.remove(str);
    }
    return Collections.unmodifiableMap(localMap);
  }

  public AuthorizeSetting getInstanceAuthorisation(String name) {
    return (AuthorizeSetting)this.u.getInstanceAuthorisations().get(name);
  }
  @Deprecated
  public Map<String, AuthorizeSetting> getInstanceAuthorisations() {
    return this.u.getInstanceAuthorisations();
  }

  public PasswordService getPasswordService() {
    return this.k;
  }

  public void updateCasConfig(CasConfig casConfig)
  {
    this.o.lock();
    try {
      Profile.Section localSection = h();
      localSection.put("casRealm.enabled", Boolean.valueOf(casConfig.enabled));
      localSection.put("casRealm.reserveSystemAccount", Boolean.valueOf(casConfig.reserveSystemAccount));
      localSection.put("casRealm.casServerUrlPrefix", casConfig.serverUrlPrefix);
      localSection.put("casRealm.casService", casConfig.service);
      String str = this.p.b(localSection);
      if ((StringUtils.isNotBlank(casConfig.attributeName)) && (!str.equalsIgnoreCase(casConfig.attributeName))) {
        this.p.a(localSection, casConfig.attributeName.trim());
      }
      f();
    } finally {
      this.o.unlock();
    }
  }

  public List<CasRule> getCasRules()
  {
    ArrayList localArrayList = new ArrayList();
    this.n.lock();
    try {
      Profile.Section localSection = h();
      Map localMap = this.p.a(localSection);
      while(localMap.entrySet().iterator().hasNext()){
    	  Map.Entry localEntry = (Map.Entry)localMap.entrySet().iterator().next();
      //for (Map.Entry localEntry : localMap.entrySet()) {
        CasRule localCasRule = new CasRule();
        localCasRule.attributeValue = ((String)localEntry.getKey());
        localCasRule.roles = ((List)localEntry.getValue());
        localArrayList.add(localCasRule);
      }
    } finally {
      this.n.unlock();
    }
    return localArrayList;
  }

  public void deleteCasAttributeRules(List<String> attributeValues)
  {
    if (CollectionUtils.isEmpty(attributeValues)) {
      return;
    }

    this.o.lock();
    try {
      Profile.Section localSection = h();
      Map localMap = this.p.a(localSection);
      for (String str : attributeValues) {
        localMap.remove(str);
      }
      this.p.a(localSection, localMap);
      f();
    } finally {
      this.o.unlock();
    }
  }

  public void addCasAttributeRule(CasRule casRule)
  {
    if (casRule == null) {
      return;
    }
    this.o.lock();
    try {
      Profile.Section localSection = h();
      Map localMap = this.p.a(localSection);
      if (localMap.containsKey(casRule.attributeValue)) {
        throw new IllegalStateException("已经存在" + casRule.attributeValue + "对应的角色信息。");
      }
      localMap.put(casRule.attributeValue, casRule.roles);
      this.p.a(localSection, localMap);
      f();
    } finally {
      this.o.unlock();
    }
  }

  public void updataCasRules(CasRuleUpdateParameter casRuleUpdate)
  {
    if ((casRuleUpdate == null) || (CollectionUtils.isEmpty(casRuleUpdate.attributeValues))) {
      return;
    }
    this.o.lock();
    try {
      Profile.Section localSection = h();
      Map localMap = this.p.a(localSection);
      List<String> localList = casRuleUpdate.attributeValues;
      for (String str : localList) {
        if (!localMap.containsKey(str)) {
          continue;
        }
        localMap.put(str, casRuleUpdate.roles);
      }
      this.p.a(localSection, localMap);
      f();
    } finally {
      this.o.unlock();
    }
  }

  public List<String> listUserGroups()
  {
    try
    {
      this.n.lock();
      ArrayList localArrayList1 = new ArrayList(this.f.keySet());
      localArrayList1.remove("LDAP_AUTHORIZED");
      ArrayList localArrayList2 = localArrayList1;
      return localArrayList2;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public void alterUserGroup(String name, UserGroup userGroup)
  {
    a(userGroup);
    try {
      this.o.lock();
      UserGroup localUserGroup = getUserGroup(name);
      if (localUserGroup == null) {
       // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USERGROUP_NOT_EXISTS, new Object[] { name }));
      }
      this.r.alterUserGroup(name, userGroup);
      reloadSecurityInfoFromDAO();
    } finally {
      this.o.unlock();
    }
  }

  public void removeUserGroup(String name)
  {
    a(name, "userGroupName");
    try {
      this.o.lock();
      UserGroup localUserGroup = getUserGroup(name);
      if (localUserGroup == null) {
        //throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USERGROUP_NOT_EXISTS, new Object[] { name }));
      }
      this.r.removeUserGroups(new String[] { name });
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock();
    }
  }

  public void addUserGroup(UserGroup userGroup)
  {
    a(userGroup);
    try {
      this.o.lock();
      UserGroup localUserGroup = getUserGroup(userGroup.name);
      if (localUserGroup != null) {
       // throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_USERGROUP_EXISTS, new Object[] { userGroup.name }));
      }
      this.r.addUserGroup(userGroup);
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock();
    }
  }

  public List<UserGroup> getAllUserGroup()
  {
    try
    {
      this.n.lock();
      ArrayList localArrayList1 = new ArrayList(this.f.values());
      localArrayList1.remove(this.f.get("LDAP_AUTHORIZED"));
      ArrayList localArrayList2 = localArrayList1;
      return localArrayList2;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  public UserGroup getUserGroup(String name)
  {
    a(name, "userGroupName");
    try {
      this.n.lock();
      UserGroup localUserGroup1 = (UserGroup)this.f.get(name);
      UserGroup localUserGroup2 = localUserGroup1 == null ? null : localUserGroup1.copy();
      return localUserGroup2;
    } finally {
      this.n.unlock(); } //throw localObject;
  }

  private void a(UserGroup paramUserGroup)
  {
    a(paramUserGroup, "userGroup");
    if (paramUserGroup.name == null)
      ;//throw new IllegalArgumentException(b.getMessage(SecurityManageResource.MANAGER_CHECKROLE_USERGROUP_NAME_NULL, new Object[0]));
  }

  public void refresh()
  {
    try {
      this.o.lock();
      reloadSecurityInfoFromDAO();

      this.o.unlock(); } finally { this.o.unlock();
    }
  }

  public void extendedUserAdded(String storageId, String username, ExtendedUserInfo user)
  {
    this.v.extendedUserAdded(storageId, username, user);
    refresh();
  }

  public void setExtendedUserStore(UsernamePasswordRealmListener listener) {
    this.v = listener;
  }

  public void onStorageStatusChanged()
  {
    reloadSecurityInfoFromDAO();
  }

  protected void setSessionManagerFactory(SessionManagerFactory sessionManagerFactory) {
    this.y = sessionManagerFactory;
  }

  static class StringArrayCompartor
  {
    List<String> a;
    List<String> b;
    List<String> c = new ArrayList();
    List<String> d = new ArrayList();

    StringArrayCompartor(String[] beford, String[] after) {
      this.a = (beford != null ? Arrays.asList(beford) : new ArrayList());
      this.b = (after != null ? Arrays.asList(after) : new ArrayList());
    }

    public void executeCompare() {
      if (CollectionUtils.isEmpty(this.a)) {
        this.c.addAll(this.b);
      } else if (CollectionUtils.isEmpty(this.b)) {
        this.d.addAll(this.a);
      } else {
        ArrayList<String> localArrayList = new ArrayList();
        localArrayList.addAll(this.a);
        localArrayList.addAll(this.b);
        for (String str : localArrayList) {
          if (!this.a.contains(str)) {
            this.c.add(str);
          }
          if (!this.b.contains(str))
            this.d.add(str);
        }
      }
    }

    List<String> a()
    {
      return this.c;
    }

    List<String> b() {
      return this.d;
    }
  }

  public static abstract interface CreateAdminUserListener
  {
    public abstract void adminUserCreated();
  }
}