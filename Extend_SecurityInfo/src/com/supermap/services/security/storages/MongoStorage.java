package com.supermap.services.security.storages;

import static com.supermap.services.rest.resources.SecurityManageResource.ROLE_DESCRIPTION_ADMIN;
import static com.supermap.services.rest.resources.SecurityManageResource.ROLE_DESCRIPTION_PORTAL_USER;
import static com.supermap.services.rest.resources.SecurityManageResource.ROLE_DESCRIPTION_PUBLISHER;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.GROUP;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.RESOURCE_TYPE_COMPONENT;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.RESOURCE_TYPE_PUBLISH;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.RESOURCE_TYPE_SERVICE;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.ROLE;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.USER;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.isAllowAccessService;
import static com.supermap.services.security.DefaultServiceBeanPermissionDAOConstants.isAllowManageComponent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.credential.PasswordService;
import org.bson.types.ObjectId;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.collect.Lists;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.WriteResult;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.supermap.server.config.CustomSecurityInfoStorageSetting;
import com.supermap.server.config.JsonStorageSetting;
import com.supermap.server.config.MongoStorageSetting;
import com.supermap.server.config.SQLSecurityInfoStorageSetting;
import com.supermap.server.config.SecurityInfoStorageSetting;
import com.supermap.server.config.SecurityInfoStorageType;
import com.supermap.services.components.commontypes.AuthorizeSetting;
import com.supermap.services.components.commontypes.AuthorizeType;
import com.supermap.services.rest.resources.SecurityManageResource;
import com.supermap.services.security.AuthenticateUsernamePasswordResult;
import com.supermap.services.security.AuthenticateUsernamePasswordResultType;
import com.supermap.services.security.MixedPermissions;
import com.supermap.services.security.QueryResult;
import com.supermap.services.security.Role;
import com.supermap.services.security.RolePermissions;
import com.supermap.services.security.SecurityConstants;
import com.supermap.services.security.ServiceBeanPermission;
import com.supermap.services.security.User;
import com.supermap.services.security.UserGroup;
import com.supermap.services.security.storages.JsonStorage.QueryingAuthorizeSetting;
import com.supermap.services.util.FastJSONUtils;
import com.supermap.services.util.IterableUtil;
import com.supermap.services.util.ProductTypeUtil;
import com.supermap.services.util.Tool;
import com.supermap.services.util.TypedResourceManager;

public class MongoStorage implements Storage {
	private static final String DB_CONFIG_FILE_NAME = "mongodb.properties";
	private File configFile;
	private static MongoClient mongo;
	private Map<String, Role> mapRoles = new HashMap<String, Role>();
	private Map<String, User> mapUsers = new HashMap<String, User>();
	private Map<String, UserGroup> mapUserGroups = new HashMap<String, UserGroup>();
	private Map<String, RolePermissions> mapRolePermissions = new HashMap<String, RolePermissions>();
	private PasswordService passwordService;
	private Map<String, RolePermissions> rolePermissions = new HashMap<String, RolePermissions>();
	private Map<String, List<ServiceBeanPermission>> serviceBeanPermissions = new HashMap<String, List<ServiceBeanPermission>>();
	private Map<String, AuthorizeSetting> authorizeSetting = new HashMap<String, AuthorizeSetting>();
	private static TypedResourceManager<SecurityManageResource> resource = new TypedResourceManager<SecurityManageResource>(SecurityManageResource.class);
	public MongoStorage(){
		super();
	}
	
	/**
	 * 存储用户的账户信息
	 */
	@Override
	public AuthenticateUsernamePasswordResult authenticate(String username,
			char[] password) {
		System.out.println("调用了authenticate方法");
		User user = this.getUser(username);
		AuthenticateUsernamePasswordResult result = new AuthenticateUsernamePasswordResult();
		if (user != null) {
			result.type = this.passwordService.passwordsMatch(password,
					user.password) ? AuthenticateUsernamePasswordResultType.VALIED
					: AuthenticateUsernamePasswordResultType.INVALID;
		}
		return result;
	}

	/**
	 * 获取用户组列表
	 */
	@Override
	public Set<String> getGroups(String username) {
		Set<String> setGroups = null;
		DB db = mongo.getDB("MetaData");
		DBCollection cltUsers = db.getCollection("Users");
		DBObject query = new BasicDBObject();
		query.put("username", username);
		DBObject objUser = cltUsers.findOne(query);
		if(objUser==null)
			return null;
		DBCollection cltRef = db.getCollection("DepartmentUserRef");
		query = new BasicDBObject();
		query.put("userid", objUser.get("_id").toString());
		DBCursor curRef = cltRef.find(query);
		DBCollection cltDepts = db.getCollection("Departments");
		if(curRef!=null&&curRef.count()>0)
			setGroups = new HashSet<String>();
		while(curRef.hasNext()){
			DBObject objRef = curRef.next();
			query = new BasicDBObject();
			query.put("_id",new ObjectId(objRef.get("departmentid").toString()));
			DBObject objDept = cltDepts.findOne(query);
			if(objDept!=null)
				setGroups.add(objDept.get("DeptName").toString());
		}
		System.out.println("line140,调用了getGroups方法，setGroups.size="+setGroups.size());
		return setGroups;
	}

	/**
	 * 获取一个户名所关联的角色列表
	 */
	@Override
	public Set<String> getRoles(String username, Set<String> groups) {
		System.out.println("调用了getRoles(username,groups)方法");
		Set<String> result = new LinkedHashSet<String>();
		if (!StringUtils.isEmpty(username)) {
			User user = this.mapUsers.get(username);
			if (user != null && !ArrayUtils.isEmpty(user.roles)) {
				result.addAll(Lists.asList(null, user.roles));
			}
		}
		if (groups != null && !groups.isEmpty()) {
			for (String groupName : groups) {
				if (StringUtils.isEmpty(groupName)) {
					continue;
				}

				UserGroup ug = this.mapUserGroups.get(groupName);
				if (ug != null && !ArrayUtils.isEmpty(ug.roles)) {
					result.addAll(Lists.asList(null, ug.roles));
				}
			}
		}
		return result;
	}

	/**
	 * 添加角色
	 */
	@Override
	public void addRole(Role role) {
		if (this.mapRoles.containsKey(role.name)) {
			throw new IllegalArgumentException("roles" + role.name
					+ " exists yet");
		}
		this.mapRoles.put(role.name, role);
		for (User user : this.mapUsers.values()) {
			boolean containUserInRole = containOne(role.users, user.name);
			boolean containRoleInUser = containOne(user.roles, role.name);
			if (containUserInRole && !containRoleInUser) {
				// 当前角色新增关联了一个用户。
				user.roles = ArrayUtils.add(user.roles, role.name);
			}
		}
		for (UserGroup userGroup : this.mapUserGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containGroupInRole = containOne(role.userGroups,
					userGroupName);
			boolean containRoleInGroup = containOne(userGroup.roles, role.name);
			if (containGroupInRole && !containRoleInGroup) {
				// 当前角色关联了一个用户组。
				userGroup.roles = ArrayUtils.add(userGroup.roles, role.name);
			}
		}
		DB db = mongo.getDB("MetaData");
		DBCollection cltRoles = db.getCollection("Roles");
		BasicDBObject objRole = new BasicDBObject();
		objRole.put("rolename", role.name);
		objRole.put("roledesc", role.name);
		WriteResult result = cltRoles.insert(objRole);
		System.out.println("调用了addRole方法");
	}

	/**
	 * 添加用户
	 */
	@Override
	public void addUser(User user) {
		if (this.mapUsers.containsKey(user.name)) {
			throw new IllegalArgumentException("user " + user.name + " exists yet");
		}
		System.out.println("line218,user.roles.length="+user.roles.length);
		this.mapUsers.put(user.name, user);
		for (Role role : this.mapRoles.values()) {
			boolean containRoleInUser = containOne(user.roles, role.name);
			boolean containUserInRole = containOne(role.users, user.name);
			if (containRoleInUser && !containUserInRole) {
				// 当前用户新增关联了一个角色。
				role.users = ArrayUtils.add(role.users, user.name);
			}
		}
		for (UserGroup userGroup : this.mapUserGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containUserInUserGroup = containOne(userGroup.users,
					user.name);
			boolean containUserGroupInUser = containOne(user.userGroups,
					userGroupName);
			if (!containUserInUserGroup && containUserGroupInUser) {
				// 当前用户新增关联了一个用户组。
				userGroup.users = ArrayUtils.add(userGroup.users, user.name);

			}
		}
		DB db = mongo.getDB("MetaData");
		DBCollection cltUsers = db.getCollection("Users");
		BasicDBObject objUser = new BasicDBObject();
		objUser.put("username", user.name);
		objUser.put("password", user.password);
		WriteResult result = cltUsers.insert(objUser);
		System.out.println("调用了addUser方法");
	}

	/**
	 * 添加用户组
	 */
	@Override
	public void addUserGroup(UserGroup usergroup) {
		System.out.println("调用了addUserGroup方法");
		
	}

	/**
	 * 修改角色
	 * @param name 角色名称
	 * @param role 角色对象
	 */
	@Override
	public void alterRole(String name, Role role) {
		
		System.out.println("调用了alterRole方法");
	}

	@Override
	public void alterUser(String arg0, User arg1) {
		
		System.out.println("调用了alterUser方法");
	}

	@Override
	public void alterUserGroup(String arg0, UserGroup arg1) {
		
		System.out.println("调用了alterUserGroup方法");
	}

	@Override
	public void dispose() {
		mongo.close();
		System.out.println("调用了dispose方法");
	}

	/**
	 * 分页获取用户组
	 */
	@Override
	public QueryResult<UserGroup> getGroups(int startIndex, int expectCount) {
		System.out.println("调用了getGroups方法");
		ArrayList<UserGroup> userGroupList = new ArrayList<UserGroup>();
		for (UserGroup userGroup : this.mapUserGroups.values()) {
			userGroupList.add(userGroup);
		}
		return this.batchGet(startIndex, expectCount, userGroupList);
	}

	/**
	 * 获取服务实例的授权信息。
	 */
	@Override
	@Deprecated
	public Map<String, AuthorizeSetting> getInstanceAuthorisations() {
		System.out.println("调用了getInstanceAuthorisations方法");
		int[] a = new int[] { RESOURCE_TYPE_SERVICE };
		List<ServiceBeanPermission> serviceBeanResults = new ArrayList<ServiceBeanPermission>();
		for (List<ServiceBeanPermission> serviceBeanPers : this.serviceBeanPermissions.values()) {
            for(ServiceBeanPermission  serviceBeanPer:serviceBeanPers){
	            if (ArrayUtils.contains(a, serviceBeanPer.resourcetype)) {
	                serviceBeanResults.add(serviceBeanPer);
	            }
            }
        }
		System.out.println("line234,serviceBeanResults.size="+serviceBeanResults.size());
		Map<String, QueryingAuthorizeSetting> querying = new HashMap<String, QueryingAuthorizeSetting>();
		System.out.println("line236,query.size="+querying.size());
		for (ServiceBeanPermission serviceBean : serviceBeanResults) {
			String instanceName = serviceBean.resource;
			//System.out.println("line239,instanceName="+instanceName);
			QueryingAuthorizeSetting setting = querying.get(instanceName);
			if (setting == null) {
				setting = new QueryingAuthorizeSetting();
				querying.put(instanceName, setting);
			}
			int permission = serviceBean.permission;
			String role = serviceBean.principal;
			if (isAllowAccessService(permission)) {
				setting.allowedRole(role);
			} else {
				setting.deniedRole(role);
			}
		}
		System.out.println("line253,quering.size="+querying.size());
		if (querying.isEmpty()) {
			return Collections.emptyMap();
		}
		Map<String, AuthorizeSetting> result = new HashMap<String, AuthorizeSetting>(
				querying.size());
		Iterator<Entry<String, QueryingAuthorizeSetting>> it = querying
				.entrySet().iterator();
		while (it.hasNext()) {
			Entry<String, QueryingAuthorizeSetting> entry = it.next();
			//System.out.println("line262,entry.getKey()="+entry.getKey());
			result.put(entry.getKey(), entry.getValue().toAuthorizeSetting());
		}
		System.out.println("line266,result.size="+result.size());
		return result;
	}

	/**
	 * 获取用户权限
	 */
	@Override
	public Set<String> getPermission(String user,
			Collection<? extends String> groups,
			Collection<? extends String> roles, Set<String> resourceIds) {
		System.out.println("调用了getPermission方法,user="+user);
		return null;
	}

	@Override
	public Set<String> getPublicServiceNames() {
		System.out.println("调用了getPublicServiceNames方法");
		return null;
	}

	/**
	 * 根据角色名获取一个角色。
	 */
	@Override
	public Role getRole(String name) {
		System.out.println("调用了getRole方法");
		return this.mapRoles.get(name);
	}

	/**
	 * 获取一个角色的权限
	 */
	@Override
	public Map<String, RolePermissions> getRolePermissions(String[] names) {
		System.out.println("调用了getRolePermissions方法");
		if (ArrayUtils.isEmpty(names)) {
			return Collections.emptyMap();
		}
		String[] roles = new String[names.length];
		for (int i = 0; i < roles.length; i++) {
			roles[i] = ROLE + names[i];
		}
		List<ServiceBeanPermission> sqlResult = new ArrayList<ServiceBeanPermission>();
		for (List<ServiceBeanPermission> serviceBeanPers : this.serviceBeanPermissions.values()) {
            for (ServiceBeanPermission serviceBeanPer : serviceBeanPers) {
                int[] a = new int[] { RESOURCE_TYPE_COMPONENT, RESOURCE_TYPE_SERVICE, RESOURCE_TYPE_PUBLISH };
                if (ArrayUtils.contains(roles, serviceBeanPer.principal) && serviceBeanPer.principaltype == 2 && ArrayUtils.contains(a, serviceBeanPer.resourcetype)) {
                    sqlResult.add(serviceBeanPer);
                }
            }
        }
		Map<String, ResolvingRolePermission> resolvingResult = new HashMap<String, ResolvingRolePermission>();

		for (ServiceBeanPermission serviceBean : sqlResult) {
			if (!StringUtils.startsWith(serviceBean.principal, ROLE)) {
				continue;
			}
			String roleName = serviceBean.principal.substring(ROLE.length());
			ResolvingRolePermission rolePermission = resolvingResult
					.get(roleName);
			if (rolePermission == null) {
				rolePermission = new ResolvingRolePermission();
				resolvingResult.put(roleName, rolePermission);
			}
			rolePermission.add(serviceBean.resourcetype, serviceBean.resource,
					serviceBean.permission);

		}

		final Map<String, RolePermissions> result = new HashMap<String, RolePermissions>();
		IterableUtil
				.iterate(
						resolvingResult.entrySet(),
						new IterableUtil.Visitor<Entry<String, ResolvingRolePermission>>() {

							@Override
							public boolean visit(
									Entry<String, ResolvingRolePermission> element) {
								result.put(element.getKey(), element.getValue()
										.toRolePermission());
								return false;
							}
						});
		return result;
	}

	/**
	 * 根据索引和数量获取角色列表。
	 * @param startIndex
	 * @param expectCount
	 * @return
	 */
	@Override
	public QueryResult<Role> getRoles(int startIndex, int expectCount) {
		System.out.println("调用了getRoles方法");
		ArrayList<Role> roleList = new ArrayList<Role>();
		for (Role role : this.mapRoles.values()) {
			roleList.add(role);
		}
		return this.batchGet(startIndex, expectCount, roleList);
	}

	@Override
	public User getUser(String username) {
		User user = null;
		DB db = mongo.getDB("MetaData");
		DBCollection colUsers = db.getCollection("Users");
		DBObject query = new BasicDBObject();
		query.put("username", username);
		DBObject objUser = colUsers.findOne(query);
		if(objUser!=null){
			user = new User();
			user.name = objUser.get("username").toString();
			user.password = objUser.get("password").toString();
		}
		System.out.println("调用了getUser方法,username="+username);
		return user;
	}

	@Override
	public QueryResult<User> getUsers(int startIndex, int expectCount) {
		System.out.println("line334:调用了getUsers方法");
		ArrayList<User> userList = new ArrayList<User>();
		List<String> ownRoles = new ArrayList<String>();
		for (User user : this.mapUsers.values()) {
			user.ownRoles = ownRoles.toArray(new String[ownRoles.size()]);
			userList.add(user);
		}
		QueryResult<User> users = batchGet(startIndex, expectCount, userList);
		System.out.println("line342,users.length="+users.records.size());
		return users;
	}

	@Override
	public void grantUser(String arg0, RolePermissions arg1) {
		
		System.out.println("调用了grantUser方法");
	}

	@Override
	public void insert(ServiceBeanPermission[] permissions) {
		if (ArrayUtils.isEmpty(permissions)) {
			return;
		}
		insertPermissionRecords(Arrays.asList(permissions));
		System.out.println("line356:调用了insert方法,permissions.length="+permissions.length);
	}

	@Override
	public void removeInstances(String[] names) {
		
		System.out.println("调用了removeInstances方法");
	}

	@Override
	public void removeRoles(String[] arg0) {
		System.out.println("调用了removeRoles方法");
		
	}

	@Override
	public void removeUserGroups(String[] arg0) {
		
		System.out.println("调用了removeUserGroups方法");
	}

	@Override
	public void removeUsers(String[] arg0) {
		
		System.out.println("调用了removeUsers方法");
	}

	@Override
	public void renameInstance(String arg0, String arg1) {
		
		System.out.println("调用了renameInstance方法");
	}

	@Override
	public void resetStorageSetting(SecurityInfoStorageSetting setting)
			throws ConnectionException {
		if (!(setting instanceof MongoStorageSetting)) {
			throw new IllegalArgumentException(
					"only recieve MongoStorageSetting");
		}
		this.init((MongoStorageSetting) setting);
	}

	@Override
	public void setFormPasswordSavedCount(int arg0) {
		
		System.out.println("调用了setFormPasswordSavedCount方法");
	}

	@Override
	public void setPasswordService(PasswordService value) {
		this.passwordService = value;
	}

	@Override
	public void setRolePermissions(String roleName, RolePermissions permission,
			ServiceBeanPermission[] permissions) {
		if (permission == null) {
			return;
		}
		final Set<ServiceBeanPermission> records = new LinkedHashSet<ServiceBeanPermission>();
		if (permission.publishEnabled) {
			records.add(new ServiceBeanPermission().publish().role(roleName));
			records.add(new ServiceBeanPermission().allowViewAllInterface()
					.role(roleName));
		}

		MixedPermissions mngPermission = permission.componentManagerPermissions;
		if (mngPermission != null) {
			if (mngPermission.permitted != null) {
				for (String com : mngPermission.permitted) {
					records.add(new ServiceBeanPermission().allowComponent(com)
							.role(roleName));
				}
			}
			if (mngPermission.denied != null) {
				for (String com : mngPermission.denied) {
					records.add(new ServiceBeanPermission().denyComponent(com)
							.role(roleName));
				}
			}
		}
		final List<String> deniedServices = new ArrayList<String>();
		MixedPermissions accessPermission = permission.instanceAccessPermissions;
		if (accessPermission != null) {
			if (accessPermission.permitted != null) {
				for (String service : accessPermission.permitted) {
					records.add(new ServiceBeanPermission().allowAccessService(
							service).role(roleName));
				}
			}
			if (accessPermission.denied != null) {
				for (String service : accessPermission.denied) {
					records.add(new ServiceBeanPermission().denyAccessService(
							service).role(roleName));
					deniedServices.add(service);
				}
			}
		}
		if (!ArrayUtils.isEmpty(permissions)) {
			records.addAll(Arrays.asList(permissions));
		}
		insertPermissionRecords(records);
		//this.persistenceToFile();
		System.out.println("调用了setRolePermissions方法");
	}

	@Override
	public void updateInstanceAuthorisation(String name,			//该方法还未真正实现，只是把代码拷贝过来了
			AuthorizeSetting authorizeSetting) {
		final Set<ServiceBeanPermission> records = new LinkedHashSet<ServiceBeanPermission>();
		if (AuthorizeType.PUBLIC.equals(authorizeSetting.type)) {
			records.add(new ServiceBeanPermission().role(
					SecurityConstants.ROLE_EVERYONE).allowAccessService(name));
		} else if (AuthorizeType.AUTHENTICATED.equals(authorizeSetting.type)) {
			records.add(new ServiceBeanPermission().role(
					SecurityConstants.ROLE_USER).allowAccessService(name));
		}
		if (!ArrayUtils.isEmpty(authorizeSetting.deniedRoles)) {
			for (String role : authorizeSetting.deniedRoles) {
				if (StringUtils.isEmpty(role)) {
					continue;
				}
				records.add(new ServiceBeanPermission().role(role)
						.denyAccessService(name));
			}
		}
		if (!ArrayUtils.isEmpty(authorizeSetting.permittedRoles)) {
			for (String role : authorizeSetting.permittedRoles) {
				if (StringUtils.isEmpty(role)) {
					continue;
				}
				records.add(new ServiceBeanPermission().role(role)
						.allowAccessService(name));
			}
		}
		int[] a = new int[] { RESOURCE_TYPE_SERVICE };
		for (List<ServiceBeanPermission> serviceBeanPers : this.serviceBeanPermissions.values()) {
            for(ServiceBeanPermission  serviceBeanPer:serviceBeanPers){
            if (ArrayUtils.contains(a, serviceBeanPer.resourcetype) && serviceBeanPer.resource.equals(name) ) {
                this.serviceBeanPermissions.get(serviceBeanPer.principal).remove(serviceBeanPer);
            }
        }
        }
        insertPermissionRecords(records);
		//this.persistenceToFile();
		System.out.println("调用了updateInstanceAuthorisation方法");
	}
	
	private void init(MongoStorageSetting setting){
		String appFilePath = Tool.getApplicationPath(setting.outputDirectory);
		//this.configFile = new File(appFilePath, DB_CONFIG_FILE_NAME);
		InputStream is=null;
		try {
			is = new FileInputStream(appFilePath+"\\"+DB_CONFIG_FILE_NAME);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}  
		Properties prop=new Properties();
		try {
			prop.load(is);
		} catch (IOException e) {
			e.printStackTrace();
		}
		//System.out.println("从配置文件获取的配置信息："+prop.getProperty("server")+":"+prop.getProperty("port"));
		mongo =  new MongoClient(prop.getProperty("server"), Integer.parseInt(prop.getProperty("port")));
		this.mapUsers = getUsers();
		this.mapRoles = getRoles();
		this.mapUserGroups = getUserGroups();
		this.serviceBeanPermissions = getServiceBeanPermissions();
	}

	@SuppressWarnings("deprecation")
	private Map<String, User> getUsers(){
		Map<String, User> mapUsers = new HashMap<String, User>();
		DB db = mongo.getDB("MetaData");
		DBCollection colUsers = db.getCollection("Users");
		DBObject query = new BasicDBObject();
		DBCursor curUser = colUsers.find(query);
		while(curUser.hasNext()){
			DBObject objUser = curUser.next();
			User user = new User();
			user.name = objUser.get("username").toString();
			user.password = objUser.get("password").toString();
			user.roles = getRolesOfUser(objUser.get("_id").toString());
			mapUsers.put(user.name, user);
		}
		System.out.println("line542,调用了getUsers方法。mapUsers.size="+mapUsers.size());
		return mapUsers;
	}
	
	@SuppressWarnings("deprecation")
	private Map<String, Role> getRoles(){
		Map<String, Role> mapRoles = new HashMap<String, Role>();
		DB db = mongo.getDB("MetaData");
		DBCollection colRoles = db.getCollection("Roles");
		DBCursor curRole = colRoles.find();
		while(curRole.hasNext()){
			DBObject objRole = curRole.next();
			Role role = new Role();
			role.name = objRole.get("rolename").toString();
			role.description = objRole.get("roledesc").toString();
			role.users = getUsersOfRole(objRole.get("_id").toString());
			mapRoles.put(role.name, role);
		}
		return mapRoles;
	}
	
	@SuppressWarnings("deprecation")
	private String[] getRolesOfUser(String userid){
		List<String> lstRoles = null;
		DB db = mongo.getDB("MetaData");
		DBCollection colUserRoles = db.getCollection("RoleUserRef");
		DBObject query = new BasicDBObject();
		query.put("userid", userid);
		DBCursor curUserRole = colUserRoles.find(query);
		while(curUserRole.hasNext()){
			lstRoles = new ArrayList<String>();
			DBObject objUserRoleRef = curUserRole.next();
			String strRoleId = objUserRoleRef.get("roleid").toString();
			DBCollection colRole = db.getCollection("Roles");
			query =  new BasicDBObject();
			query.put("_id", new ObjectId(strRoleId));
			DBObject objRole = colRole.findOne(query);
			if(objRole!=null)
				lstRoles.add(objRole.get("rolename").toString());
		}
		if(lstRoles!=null){
			String[] arrResult = new String[lstRoles.size()];
			for(int i=0;i<lstRoles.size();i++)
				arrResult[i] = lstRoles.get(i);
			return arrResult;
		}
		return null;
	}
	
	@SuppressWarnings("deprecation")
	private String[] getUsersOfRole(String roleId){
		List<String> lstUsers = null;
		DB db = mongo.getDB("MetaData");
		DBCollection colUserRoles = db.getCollection("RoleUserRef");
		DBObject query = new BasicDBObject();
		query.put("roleid", roleId);
		DBCursor curUserRole = colUserRoles.find(query);
		while(curUserRole.hasNext()){
			lstUsers = new ArrayList<String>();
			DBObject objUserRoleRef = curUserRole.next();
			String strUserId = objUserRoleRef.get("userid").toString();
			DBCollection colUsers = db.getCollection("Users");
			query =  new BasicDBObject();
			query.put("_id", new ObjectId(strUserId));
			DBObject objUser = colUsers.findOne(query);
			if(objUser!=null)
				lstUsers.add(objUser.get("username").toString());
		}
		if(lstUsers!=null){
			String[] arrResult = new String[lstUsers.size()];
			for(int i=0;i<lstUsers.size();i++)
				arrResult[i] = lstUsers.get(i);//System.out.println("line615,arrResult.length="+arrResult.length);
			return arrResult;
		}
		return null;
	}
	
	private Map<String, UserGroup> getUserGroups(){
		Map<String, UserGroup> mapUserGroups = null;
		DB db = mongo.getDB("MetaData");
		DBCollection cltDepts = db.getCollection("Departments");
		DBCollection cltRef = db.getCollection("DepartmentUserRef");
		DBCollection cltUsers = db.getCollection("Users");
		DBCursor curDept = cltDepts.find();
		if(curDept.count()>0)
			mapUserGroups = new HashMap<String, UserGroup>();
		while(curDept.hasNext()){
			UserGroup userGroup = new UserGroup();
			DBObject objDept = curDept.next();
			String strDeptName = objDept.get("DeptName").toString();
			String strDeptId = objDept.get("_id").toString();
			userGroup.name = strDeptName;
			DBObject query = new BasicDBObject();
			query.put("departmentid", strDeptId);
			DBCursor curRef = cltRef.find(query);
			int i=0;
			String strUsers = "";
			while(curRef.hasNext()){
				DBObject objRef = curRef.next();
				DBObject queryUser = new BasicDBObject();
				queryUser.put("_id", new ObjectId(objRef.get("userid").toString()));
				DBObject objUser = cltUsers.findOne(queryUser);
				if(objUser!=null){
					strUsers+=objUser.get("username").toString()+",";
				}
				i++;
			}
			if(strUsers.length()>0)
				strUsers=strUsers.substring(0, strUsers.length()-1);
			System.out.println("line 679,userGroupName="+strDeptName+",users="+strUsers);
			userGroup.users = strUsers.split(",");
			mapUserGroups.put(userGroup.name, userGroup);
		}
		System.out.println("line678,mapUserGroups.size="+mapUserGroups.size());
		return mapUserGroups;
	}
	
	private Map<String, List<ServiceBeanPermission>>  getServiceBeanPermissions(){
		Map<String, List<ServiceBeanPermission>> mapServicePermissions = new HashMap<String, List<ServiceBeanPermission>>();
		for (Role role : this.mapRoles.values()) {
			String strRoleName = role.name;
			List<String> lstPris = getRolePrivileges(strRoleName);
			if(lstPris!=null){
				List<ServiceBeanPermission> lstPermission = new ArrayList<ServiceBeanPermission>();
				for(int i=0;i<lstPris.size();i++){
					ServiceBeanPermission permission = new ServiceBeanPermission();
					permission.permission = 1;
					permission.principal = "ROLE^" + strRoleName;
					permission.principaltype = 2;
					permission.resource = lstPris.get(i);
					permission.resourcetype = 7;
					permission.shiroPermission = "services:access:instance^" + lstPris.get(i);
					lstPermission.add(permission);
				}
				mapServicePermissions.put(strRoleName, lstPermission);
			}
		}
		return mapServicePermissions;
	}
	
	@SuppressWarnings("deprecation")
	private List<String> getRolePrivileges(String strRoleName){
		List<String> lstPris = null;
		DB db = mongo.getDB("MetaData");
		DBCollection colRoles = db.getCollection("Roles");
		DBObject query = new BasicDBObject();
		query.put("rolename",strRoleName);
		DBObject objRole = colRoles.findOne(query);
		if(objRole!=null){
			String strRoleId = objRole.get("_id").toString();
			DBCollection cltRolePris = db.getCollection("RolePrivileges");
			query = new BasicDBObject();
			query.put("RoleId", strRoleId);
			query.put("ResTypeId", "服务");
			DBCursor curPri = cltRolePris.find(query);
			if(curPri.count()>0){
				lstPris = new ArrayList<String>();
				while(curPri.hasNext()){
					DBObject objPri = curPri.next();
					String strResId = objPri.get("ResId").toString();
					DB dbService = mongo.getDB("PFMP_ServiceMetadata");
					DBCollection cltService = dbService.getCollection("MDS_SERVICEREGISTER");
					query = new BasicDBObject();
					query.put("_id", new ObjectId(strResId));
					DBObject objService = cltService.findOne(query);
					if(objService!=null){
						String strServiceURL = objService.get("SERVICEURL").toString();
						lstPris.add(strServiceURL.substring(strServiceURL.toLowerCase().indexOf("/services/")+10));
					}
				}
			}
		}
		return lstPris;
	}
	
	/**
	 * 分页批量查询列表
	 * @param startIndex
	 * @param expectCount
	 * @param list
	 * @return
	 */
	private <T> QueryResult<T> batchGet(int startIndex, int expectCount,
			List<T> list) {
		int actualCount = expectCount;
		int size = list.size();
		if (expectCount > size - startIndex || expectCount == 0) {
			actualCount = size - startIndex;
		}
		List<T> founds = new ArrayList<T>();
		if (startIndex <= size) {
			int index = startIndex;
			int findCount = 0;
			while (findCount < actualCount) {
				founds.add(list.get(index));
				index++;
				findCount++;
			}
		}
		QueryResult<T> queryResult = new QueryResult<T>();
		queryResult.records = founds;
		queryResult.totalCount = size;
		return queryResult;
	}
		
	private void insertPermissionRecords(Iterable<ServiceBeanPermission> records) {
		for (ServiceBeanPermission record : records) {
			if (this.serviceBeanPermissions.containsKey(record.principal)) {
				this.serviceBeanPermissions.get(record.principal).add(record);
			} else {
				List<ServiceBeanPermission> list = new ArrayList<ServiceBeanPermission>();
				list.add(record);
				this.serviceBeanPermissions.put(record.principal, list);
			}

		}
	}

	// 解析角色授权信息，使之转化为可存储的字符串。
	private static class ResolvingRolePermission {
		List<String> allowedCom = new LinkedList<String>();
		List<String> deniedCom = new LinkedList<String>();
		List<String> allowedService = new LinkedList<String>();
		List<String> deniedService = new LinkedList<String>();
		boolean isPublisher = false;

		public RolePermissions toRolePermission() {
			RolePermissions result = new RolePermissions();
			result.publishEnabled = isPublisher;
			result.componentManagerPermissions = new MixedPermissions();
			result.componentManagerPermissions.denied = toArray(deniedCom);
			result.componentManagerPermissions.permitted = toArray(allowedCom);
			result.instanceAccessPermissions = new MixedPermissions();
			result.instanceAccessPermissions.denied = toArray(deniedService);
			result.instanceAccessPermissions.permitted = toArray(allowedService);
			return result;
		}

		void add(int resourceType, String resourceName, int perm) {
			List<String> list = null;
			switch (resourceType) {
			case RESOURCE_TYPE_PUBLISH: {
				isPublisher = true;
				break;
			}
			case RESOURCE_TYPE_COMPONENT: {
				list = isAllowManageComponent(perm) ? allowedCom : deniedCom;
				break;
			}
			case RESOURCE_TYPE_SERVICE: {
				list = isAllowAccessService(perm) ? allowedService
						: deniedService;
				break;
			}
			}
			if (list != null) {
				list.add(resourceName);
			}
		}
	}
	
	private static String[] toArray(List<String> list) {
		return list.isEmpty() ? ArrayUtils.EMPTY_STRING_ARRAY : list
				.toArray(new String[list.size()]);
	}
	
	// 查询是否存在某个角色。
	private boolean containOne(String[] roles, String theRole) {
		if (ArrayUtils.isEmpty(roles)) {
			return false;
		}
		return ArrayUtils.contains(roles, theRole);
	}
		
	// 添加系统预定义角色，包括"SYSTEM,ADMIN,PORTAL_USER,PUBLISHER"。
	private void addPredefinedRoles() {
		insertRole(SecurityConstants.ROLE_SYSTEM, StringUtils.EMPTY);
		insertRole(SecurityConstants.ROLE_ADMIN,
				resource.message(ROLE_DESCRIPTION_ADMIN));
		if (ProductTypeUtil.isPortal()) {
			insertRole(SecurityConstants.ROLE_PORTAL_USER,
					resource.message(ROLE_DESCRIPTION_PORTAL_USER));
		}
		insertRole(SecurityConstants.ROLE_PUBLISHER,
				resource.message(ROLE_DESCRIPTION_PUBLISHER));
		//this.persistenceToFile();
	}

	// 添加系统预定义的用户组。
	private void addPredefinedGroups() {
		insertGroups(SecurityConstants.GROUP_THIRD_PART_AUTHORIZED,
				StringUtils.EMPTY);
		insertGroups(SecurityConstants.GROUP_LDAP_AUTHORIZED, StringUtils.EMPTY);
		//this.persistenceToFile();
	}
	
	// 添加角色。
	private void insertRole(String roleName, String description) {
		Role role = new Role();
		role.name = roleName;
		role.description = description;
		this.mapRoles.put(roleName, role);
	}

	// 添加用户组。
	private void insertGroups(String GroupName, String description) {
		UserGroup userGroup = new UserGroup();
		userGroup.name = GroupName;
		userGroup.description = description;
		this.mapUserGroups.put(GroupName, userGroup);
	}
		
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		MongoStorage storage = new MongoStorage();
		mongo = new MongoClient("localhost",27018);
		storage.mapUsers = storage.getUsers();
		storage.mapRoles = storage.getRoles();
		storage.mapUserGroups = storage.getUserGroups();
		storage.serviceBeanPermissions = storage.getServiceBeanPermissions();
		Map<String, RolePermissions> mapPermissions = storage.getRolePermissions(new String[]{"利用科","利用中心","地籍管理","匿名角色"});
		 Iterator<String> it = mapPermissions.keySet().iterator();  
	        while(it.hasNext()){  
	             String key;     
	             RolePermissions permission;     
	             key=it.next().toString();     
	             permission=(RolePermissions) mapPermissions.get(key);     
	             System.out.println(key+"--"+permission.toString());     
	        }  
	}
}
