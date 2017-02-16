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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.credential.PasswordService;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.collect.Lists;
import com.supermap.server.config.JsonStorageSetting;
import com.supermap.server.config.SecurityInfoStorageSetting;
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
import com.supermap.services.util.FastJSONUtils;
import com.supermap.services.util.IterableUtil;
import com.supermap.services.util.ProductTypeUtil;
import com.supermap.services.util.Tool;
import com.supermap.services.util.TypedResourceManager;

public class JsonStorage implements Storage {
	private static final String SECURITY_FILE_NAME = "security.json";
	private static final String UTF_8 = "utf-8";
	private static final String TAG_USERS = "users";
	private static final String TAG_ROLES = "roles";
	private static final String TAG_USERGROUPS = "userGroups";
	private static final String TAG_ROLEPERMISSIONS = "rolePermissions";
	private static final String TAG_AUTHORIZESETTING = "authorizeSetting";
	private static final String TAG_SERVICEBEANPERMISSIONS = "serviceBeanPermissions";
	private File storageFile;
	private Map<String, Role> roles = new HashMap<String, Role>();
	private Map<String, User> users = new HashMap<String, User>();
	private Map<String, UserGroup> userGroups = new HashMap<String, UserGroup>();
	private Map<String, RolePermissions> rolePermissions = new HashMap<String, RolePermissions>();
	private Map<String, List<ServiceBeanPermission>> serviceBeanPermissions = new HashMap<String, List<ServiceBeanPermission>>();
	private Map<String, AuthorizeSetting> authorizeSetting = new HashMap<String, AuthorizeSetting>();
	private Set<String> publicServiceNames = Collections.emptySet();
	private PasswordService passwordService;
	private static TypedResourceManager<SecurityManageResource> resource = new TypedResourceManager<SecurityManageResource>(
			SecurityManageResource.class);
	private static final Collection<String> PUBLISHER_PERMISSIONS = Collections
			.unmodifiableList(Arrays.asList(StringUtils
					.split("interface:*,instance:*,component:*,componentset:*,provider:*,providerset:*,publish",
							',')));

	// 设置使用扩展的json存储方式。
	@Override
	public void resetStorageSetting(SecurityInfoStorageSetting setting) {
		if (!(setting instanceof JsonStorageSetting)) {
			throw new IllegalArgumentException(
					"only recieve JsonStorageSetting");
		}
		this.init((JsonStorageSetting) setting);
	}

	// 读取配置的存储位置，并初始化一个json文件，用于存储安全信息。
	private void init(JsonStorageSetting setting) {
		String appFilePath = Tool.getApplicationPath(setting.outputDirectory);
		this.storageFile = new File(appFilePath, SECURITY_FILE_NAME);
		if (!this.storageFile.exists()) {
			if (!this.storageFile.getParentFile().exists()) {
				try {
					FileUtils.forceMkdirParent(this.storageFile);
				} catch (IOException e) {
					throw new IllegalStateException(
							"failed to make storage directory ");
				}
			}
			try {
				this.storageFile.createNewFile();
			} catch (IOException e) {
				throw new IllegalStateException("failed to make storage file ");
			}
			this.addPredefinedRoles();
			this.addPredefinedGroups();
		} else {
			this.setMapContent();
		}
	}

	@SuppressWarnings("unchecked")
	private void setMapContent() {
		try {
			String json = FileUtils.readFileToString(this.storageFile, UTF_8);
			Map<String, ?> statusMap = FastJSONUtils.parse(json, HashMap.class);
			if (statusMap.containsKey(TAG_USERS)) {
				this.users = (Map<String, User>) statusMap.get(TAG_USERS);
			}
			if (statusMap.containsKey(TAG_ROLES)) {
				this.roles = (Map<String, Role>) statusMap.get(TAG_ROLES);
			}
			if (statusMap.containsKey(TAG_USERGROUPS)) {
				this.userGroups = (Map<String, UserGroup>) statusMap
						.get(TAG_USERGROUPS);
			}
			if (statusMap.containsKey(TAG_ROLEPERMISSIONS)) {
				this.rolePermissions = (Map<String, RolePermissions>) statusMap
						.get(TAG_ROLEPERMISSIONS);
			}
			if (statusMap.containsKey(TAG_AUTHORIZESETTING)) {
				this.authorizeSetting = (Map<String, AuthorizeSetting>) statusMap
						.get(TAG_AUTHORIZESETTING);
			}
			if (statusMap.containsKey(TAG_SERVICEBEANPERMISSIONS)) {
				this.serviceBeanPermissions = (Map<String, List<ServiceBeanPermission>>) statusMap
						.get(TAG_SERVICEBEANPERMISSIONS);
			}
		} catch (IOException e) {
			throw new IllegalStateException("JsonStorage init failed ");
		}
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
		this.persistenceToFile();
	}

	// 添加系统预定义的用户组。
	private void addPredefinedGroups() {
		insertGroups(SecurityConstants.GROUP_THIRD_PART_AUTHORIZED,
				StringUtils.EMPTY);
		insertGroups(SecurityConstants.GROUP_LDAP_AUTHORIZED, StringUtils.EMPTY);
		this.persistenceToFile();
	}

	// 把安全信息的当前状态，包括所有用户、角色、用户组以及权限的状态持久化到存储文件中。
	private void persistenceToFile() {
		Map<String, Object> status = new HashMap<String, Object>();
		status.put(TAG_USERS, users);
		status.put(TAG_ROLES, roles);
		status.put(TAG_USERGROUPS, userGroups);
		status.put(TAG_ROLEPERMISSIONS, rolePermissions);
		status.put(TAG_AUTHORIZESETTING, authorizeSetting);
		status.put(TAG_SERVICEBEANPERMISSIONS, serviceBeanPermissions);
		String jsonStatus = FastJSONUtils.toFastJson(status);
		jsonStatus = jsonFormat(jsonStatus);
		try {
			FileUtils.write(this.storageFile, jsonStatus, UTF_8);
		} catch (IOException e) {
			System.out.println("fail to persistence to "
					+ this.storageFile.getAbsolutePath());
		}
	}

	// 格式化JSON。
	private String jsonFormat(String jsonStatus) {
		try {
			JSONObject jsonObject = new JSONObject(jsonStatus);
			return jsonObject.toString(4);
		} catch (JSONException e1) {
			// 永远走不到这里
			return "";
		}
	}

	// 添加角色。
	private void insertRole(String roleName, String description) {
		Role role = new Role();
		role.name = roleName;
		role.description = description;
		this.roles.put(roleName, role);
	}

	// 添加用户组。
	private void insertGroups(String GroupName, String description) {
		UserGroup userGroup = new UserGroup();
		userGroup.name = GroupName;
		userGroup.description = description;
		this.userGroups.put(GroupName, userGroup);
	}

	// 根据角色获取用户列表。
	@Override
	public QueryResult<User> getUsers(int startIndex, int expectCount) {
		ArrayList<User> userList = new ArrayList<User>();
		List<String> ownRoles = new ArrayList<String>();
		for (User user : this.users.values()) {
			user.ownRoles = ownRoles.toArray(new String[ownRoles.size()]);
			userList.add(user);
		}
		return batchGet(startIndex, expectCount, userList);
	}

	// 根据用户名获取单个用户。
	@Override
	public User getUser(String name) {
		return this.users.get(name);
	}

	// 添加用户。
	@Override
	public void addUser(User toAdd) {
		if (this.users.containsKey(toAdd.name)) {
			throw new IllegalArgumentException("user " + toAdd.name
					+ " exists yet");
		}
		this.users.put(toAdd.name, toAdd);
		for (Role role : this.roles.values()) {
			boolean containRoleInUser = containOne(toAdd.roles, role.name);
			boolean containUserInRole = containOne(role.users, toAdd.name);
			if (containRoleInUser && !containUserInRole) {
				// 当前用户新增关联了一个角色。
				role.users = ArrayUtils.add(role.users, toAdd.name);
			}
		}
		for (UserGroup userGroup : this.userGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containUserInUserGroup = containOne(userGroup.users,
					toAdd.name);
			boolean containUserGroupInUser = containOne(toAdd.userGroups,
					userGroupName);
			if (!containUserInUserGroup && containUserGroupInUser) {
				// 当前用户新增关联了一个用户组。
				userGroup.users = ArrayUtils.add(userGroup.users, toAdd.name);

			}
		}
		this.persistenceToFile();
	}

	// 批量删除用户。
	@Override
	public void removeUsers(String[] names) {
		for (String name : names) {
			User user = this.users.get(name);
			this.users.remove(name);
			for (Role role : this.roles.values()) {
				boolean containUserInRole = containOne(role.users, user.name);
				if (containUserInRole) {
					// 当前用户解除关联了一个角色。
					role.users = ArrayUtils
							.removeElement(role.users, user.name);
				}
			}
			for (UserGroup userGroup : this.userGroups.values()) {
				boolean containUserInGroup = containOne(userGroup.users,
						user.name);
				if (containUserInGroup) {
					// 当前用户解除关联了一个用户组。
					userGroup.users = ArrayUtils.removeElement(userGroup.users,
							user.name);

				}
			}

		}
		this.persistenceToFile();
	}

	// 修改用户信息，包括增加/减少关联的角色，增加/减少关联的用户组。
	@Override
	public void alterUser(String name, User user) {
		this.users.put(name, user);
		for (Role role : this.roles.values()) {
			boolean containRoleInUser = containOne(user.roles, role.name);
			boolean containUserInRole = containOne(role.users, user.name);
			if (containRoleInUser && !containUserInRole) {
				// 当前用户新增关联了一个角色。
				role.users = ArrayUtils.add(role.users, user.name);
			} else if (!containRoleInUser && containUserInRole) {
				// 当前用户解除关联了一个角色。
				role.users = ArrayUtils.removeElement(role.users, user.name);
			}
		}
		for (UserGroup userGroup : this.userGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containRoleInUser = containOne(userGroup.users, user.name);
			boolean containUserInRole = containOne(user.userGroups,
					userGroupName);
			if (containRoleInUser && !containUserInRole) {
				// 当前用户解除关联了一个用户组。
				userGroup.users = ArrayUtils.removeElement(userGroup.users,
						user.name);

			} else if (!containRoleInUser && containUserInRole) {
				// 当前用户新增关联了一个用户组。
				userGroup.roles = ArrayUtils
						.add(userGroup.users, userGroupName);
			}
		}
		this.persistenceToFile();
	}

	// 添加用户组及关联的角色信息。
	@Override
	public void addUserGroup(UserGroup toAdd) {
		if (this.userGroups.containsKey(toAdd.name)) {
			throw new IllegalArgumentException("userGroups " + toAdd.name
					+ " exists yet");
		}
		this.userGroups.put(toAdd.name, toAdd);
		for (Role role : this.roles.values()) {
			boolean containRoleInGroup = containOne(toAdd.roles, role.name);
			boolean containGroupInRole = containOne(role.userGroups, toAdd.name);
			if (containRoleInGroup && !containGroupInRole) {
				// 当前用户组新增关联了一个角色。
				role.userGroups = ArrayUtils.add(role.userGroups, toAdd.name);
			}
		}
		for (User user : this.users.values()) {
			boolean containUserInGroup = containOne(toAdd.users, user.name);
			boolean containGroupInUser = containOne(user.userGroups, toAdd.name);
			if (containUserInGroup && !containGroupInUser) {
				// 当前用户组新增关联了一个用户。
				user.userGroups = ArrayUtils.add(user.userGroups, toAdd.name);
			}
		}
		this.persistenceToFile();
	}

	// 修改用户组信息，包括增加/减少关联的角色，增加/减少关联的用户组。
	@Override
	public void alterUserGroup(String name, UserGroup userGroup) {
		this.userGroups.put(name, userGroup);
		for (User user : this.users.values()) {
			String userName = user.name;
			boolean containGroupInUser = containOne(user.userGroups,
					userGroup.name);
			boolean containUserInGroup = containOne(userGroup.users, userName);
			if (containGroupInUser && !containUserInGroup) {
				// 当前用户组解除关联了一个用户。
				user.userGroups = ArrayUtils.removeElement(user.userGroups,
						userGroup.name);
			} else if (!containGroupInUser && containUserInGroup) {
				// 当前用户新增关联了一个用户。
				user.userGroups = ArrayUtils.add(user.userGroups,
						userGroup.name);

			}
		}
		for (Role role : this.roles.values()) {
			String roleName = role.name;
			boolean containGroupInRole = containOne(role.userGroups,
					userGroup.name);
			boolean containRoleInGroup = containOne(userGroup.roles, roleName);
			if (containGroupInRole && !containRoleInGroup) {
				// 当前用户组新增关联了一个角色。
				role.userGroups = ArrayUtils.removeElement(role.userGroups,
						userGroup.name);
			} else if (!containGroupInRole && containRoleInGroup) {
				// 当前用户组解除关联了一个角色。
				role.userGroups = ArrayUtils.add(role.userGroups,
						userGroup.name);

			}
		}
		this.persistenceToFile();

	}

	// 删除用户组。
	@Override
	public void removeUserGroups(String[] names) {
		for (String name : names) {
			UserGroup userGroup = this.userGroups.get(name);
			this.userGroups.remove(name);
			for (Role role : this.roles.values()) {
				boolean containRoleInGroup = containOne(role.userGroups,
						userGroup.name);
				if (containRoleInGroup) {
					// 当前用户组解除关联了一个角色。
					role.userGroups = ArrayUtils.removeElement(role.userGroups,
							userGroup.name);
				}
			}
			for (User user : this.users.values()) {
				boolean containUserInGroup = containOne(user.userGroups,
						userGroup.name);
				if (containUserInGroup) {
					// 当前用户组解除关联了一个用户。
					user.userGroups = ArrayUtils.removeElement(user.userGroups,
							userGroup.name);
				}
			}
		}
		this.persistenceToFile();

	}

	// 获取用户组。
	@Override
	public QueryResult<UserGroup> getGroups(int startIndex, int expectCount) {
		ArrayList<UserGroup> userGroupList = new ArrayList<UserGroup>();
		for (UserGroup userGroup : this.userGroups.values()) {
			userGroupList.add(userGroup);
		}
		return this.batchGet(startIndex, expectCount, userGroupList);

	}

	// 添加角色。
	@Override
	public void addRole(Role toAdd) {
		if (this.roles.containsKey(toAdd.name)) {
			throw new IllegalArgumentException("roles" + toAdd.name
					+ " exists yet");
		}
		this.roles.put(toAdd.name, toAdd);
		for (User user : this.users.values()) {
			boolean containUserInRole = containOne(toAdd.users, user.name);
			boolean containRoleInUser = containOne(user.roles, toAdd.name);
			if (containUserInRole && !containRoleInUser) {
				// 当前角色新增关联了一个用户。
				user.roles = ArrayUtils.add(user.roles, toAdd.name);
			}
		}
		for (UserGroup userGroup : this.userGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containGroupInRole = containOne(toAdd.userGroups,
					userGroupName);
			boolean containRoleInGroup = containOne(userGroup.roles, toAdd.name);
			if (containGroupInRole && !containRoleInGroup) {
				// 当前角色关联了一个用户组。
				userGroup.roles = ArrayUtils.add(userGroup.roles, toAdd.name);
			}
		}
		this.persistenceToFile();
	}

	// 修改角色。
	@Override
	public void alterRole(String name, Role role) {
		this.roles.put(name, role);
		String roleName = role.name;
		// 修改关联的用户信息
		for (User user : this.users.values()) {
			String userName = user.name;
			boolean containRoleInUser = containOne(user.roles, roleName);
			boolean containUserInRole = containOne(role.users, userName);
			if (containRoleInUser && !containUserInRole) {
				// 当前角色解除关联了一个用户。
				user.roles = ArrayUtils.removeElement(user.roles, roleName);

			} else if (!containRoleInUser && containUserInRole) {
				// 当前角色新增关联了一个用户。
				user.roles = ArrayUtils.add(user.roles, roleName);
			}
		}
		for (UserGroup userGroup : this.userGroups.values()) {
			String userGroupName = userGroup.name;
			boolean containRoleInUser = containOne(userGroup.roles, roleName);
			boolean containUserInRole = containOne(role.userGroups,
					userGroupName);
			if (containRoleInUser && !containUserInRole) {
				// 当前角色解除关联了一个用户组。
				userGroup.roles = ArrayUtils.removeElement(userGroup.roles,
						roleName);

			} else if (!containRoleInUser && containUserInRole) {
				// 当前角色新增关联了一个用户组。
				userGroup.roles = ArrayUtils.add(userGroup.roles, roleName);
			}
		}
		this.persistenceToFile();
	}

	// 批量删除角色。
	@Override
	public void removeRoles(String[] names) {
		for (String name : names) {
			Role role = this.roles.get(name);
			this.roles.remove(name);
			for (User user : this.users.values()) {
				boolean containRoleInUser = containOne(user.roles, role.name);
				if (containRoleInUser) {
					// 当前角色解除关联了一个用户。
					user.roles = ArrayUtils
							.removeElement(user.roles, role.name);
				}
			}
			for (UserGroup userGroup : this.userGroups.values()) {
				boolean containRoleInGroup = containOne(userGroup.roles,
						role.name);
				if (containRoleInGroup) {
					// 当前角色解除关联了一个用户组。
					userGroup.roles = ArrayUtils.removeElement(userGroup.roles,
							role.name);
				}
			}
		}
		this.persistenceToFile();
	}

	// 根据角色名获取一个角色。
	@Override
	public Role getRole(String name) {
		return this.roles.get(name);
	}

	// 获取用户组列表。
	@Override
	public Set<String> getGroups(String username) {
		Set<String> result = new LinkedHashSet<String>();
		if (!StringUtils.isEmpty(username)) {
			User user = this.users.get(username);
			if (user != null && !ArrayUtils.isEmpty(user.userGroups)) {
				result.addAll(Lists.asList(null, user.userGroups));
			}
		}
		return result;
	}

	// 获取一个户名所关联的角色列表。
	@Override
	public Set<String> getRoles(String username, Set<String> groups) {

		Set<String> result = new LinkedHashSet<String>();
		if (!StringUtils.isEmpty(username)) {
			User user = this.users.get(username);
			if (user != null && !ArrayUtils.isEmpty(user.roles)) {
				result.addAll(Lists.asList(null, user.roles));
			}
		}
		if (groups != null && !groups.isEmpty()) {
			for (String groupName : groups) {
				if (StringUtils.isEmpty(groupName)) {
					continue;
				}

				UserGroup ug = this.userGroups.get(groupName);
				if (ug != null && !ArrayUtils.isEmpty(ug.roles)) {
					result.addAll(Lists.asList(null, ug.roles));
				}
			}
		}
		return result;
	}

	// 根据索引和数量获取角色列表。
	@Override
	public QueryResult<Role> getRoles(int startIndex, int expectCount) {
		ArrayList<Role> roleList = new ArrayList<Role>();
		for (Role role : this.roles.values()) {
			roleList.add(role);
		}
		return this.batchGet(startIndex, expectCount, roleList);
	}

	// 获取发布的所有服务列表。
	@Override
	public Set<String> getPublicServiceNames() {
		return publicServiceNames;
	}

	// 为角色设置权限。
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
		this.persistenceToFile();
	}

	// 获取一个用户的权限。
	@Override
	public Set<String> getPermission(String user,
			Collection<? extends String> groups,
			Collection<? extends String> roles, Set<String> resourceIds) {
		Set<String> result = new LinkedHashSet<String>();
		int initialCapacity = 1;
		initialCapacity += groups == null ? 0 : groups.size();
		initialCapacity += roles == null ? 0 : roles.size();
		final Set<String> principals = new LinkedHashSet<String>(
				initialCapacity);
		if (StringUtils.isNotEmpty(user)) {
			principals.add(USER + user);
		}
		add(principals, groups, GROUP);
		add(principals, roles, ROLE);
		if (principals.isEmpty()) {
			return Collections.emptySet();
		}
		final boolean isPublisher = principals.remove("ROLE^PUBLISHER");
		if (isPublisher) {
			result.addAll(PUBLISHER_PERMISSIONS);
		} else {
			for (String principal : principals) {
                if (this.serviceBeanPermissions.containsKey(principal)) {
                    List<ServiceBeanPermission> sps = this.serviceBeanPermissions.get(principal);
                    if (sps == null) {
                        continue;
                    }
                    for (ServiceBeanPermission sp : sps) {
                    	System.out.println("用户"+user+"权限信息："+sp.shiroPermission);
                        result.add(sp.shiroPermission);
                    }
                }
            }
		}
		return result;

	}

	// 获取一个角色的权限。
	@Override
	public Map<String, RolePermissions> getRolePermissions(String[] names) {
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
                if (ArrayUtils.contains(roles, serviceBeanPer) && serviceBeanPer.principaltype == 2 && ArrayUtils.contains(a, serviceBeanPer.resourcetype)) {
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

	// 更新一个服务实例的授权信息。
	@Override
	public void updateInstanceAuthorisation(String name,
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
		this.persistenceToFile();
	}

	// 获取服务实例的授权信息。
	@Override
	public Map<String, AuthorizeSetting> getInstanceAuthorisations() {
		int[] a = new int[] { RESOURCE_TYPE_SERVICE };
		List<ServiceBeanPermission> serviceBeanResults = new ArrayList<ServiceBeanPermission>();
		for (List<ServiceBeanPermission> serviceBeanPers : this.serviceBeanPermissions.values()) {
            for(ServiceBeanPermission  serviceBeanPer:serviceBeanPers){
            if (ArrayUtils.contains(a, serviceBeanPer.resourcetype)) {
                serviceBeanResults.add(serviceBeanPer);
            }
            }
        }
		Map<String, QueryingAuthorizeSetting> querying = new HashMap<String, QueryingAuthorizeSetting>();
		for (ServiceBeanPermission serviceBean : serviceBeanResults) {
			String instanceName = serviceBean.resource;
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
		if (querying.isEmpty()) {
			return Collections.emptyMap();
		}
		Map<String, AuthorizeSetting> result = new HashMap<String, AuthorizeSetting>(
				querying.size());
		Iterator<Entry<String, QueryingAuthorizeSetting>> it = querying
				.entrySet().iterator();
		while (it.hasNext()) {
			Entry<String, QueryingAuthorizeSetting> entry = it.next();
			result.put(entry.getKey(), entry.getValue().toAuthorizeSetting());
		}
		return result;
	}

	@Override
	public void grantUser(String username, RolePermissions permission) {
	}

	// 增加一条权限信息。
	@Override
	public void insert(ServiceBeanPermission[] permissions) {
		if (ArrayUtils.isEmpty(permissions)) {
			return;
		}
		insertPermissionRecords(Arrays.asList(permissions));
		this.persistenceToFile();
	}

	@Override
	public void setPasswordService(PasswordService value) {
		this.passwordService = value;
	}

	// 存储用户的账户信息。
	@Override
	public AuthenticateUsernamePasswordResult authenticate(String username,
			char[] password) {
		User user = this.getUser(username);
		AuthenticateUsernamePasswordResult result = new AuthenticateUsernamePasswordResult();
		if (user != null) {
			result.type = this.passwordService.passwordsMatch(password,
					user.password) ? AuthenticateUsernamePasswordResultType.VALIED
					: AuthenticateUsernamePasswordResultType.INVALID;
		}
		return result;
	}

	private void add(Set<String> toAddIn, Collection<? extends String> toAdd,
			String prefix) {
		if (toAdd == null || toAdd.isEmpty()) {
			return;
		}
		for (String str : toAdd) {
			toAddIn.add(prefix + str);
		}
	}

	// 查询是否存在某个角色。
	private boolean containOne(String[] roles, String theRole) {
		if (ArrayUtils.isEmpty(roles)) {
			return false;
		}
		return ArrayUtils.contains(roles, theRole);
	}

	// 批量查询。
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

	static class QueryingAuthorizeSetting {
		AuthorizeType type;
		Set<String> deniedRoles = new LinkedHashSet<String>();
		Set<String> allowedRoles = new LinkedHashSet<String>();

		QueryingAuthorizeSetting allowedRole(String value) {
			String role = value.substring(ROLE.length());
			if (type == null && SecurityConstants.ROLE_USER.equals(role)) {
				type = AuthorizeType.AUTHENTICATED;
			} else if (SecurityConstants.ROLE_EVERYONE.equals(role)) {
				type = AuthorizeType.PUBLIC;
			} else {
				allowedRoles.add(role);
			}
			return this;
		}

		QueryingAuthorizeSetting deniedRole(String value) {
			deniedRoles.add(value.substring(ROLE.length()));
			return this;
		}

		AuthorizeSetting toAuthorizeSetting() {
			AuthorizeSetting result = new AuthorizeSetting();
			result.type = type == null ? AuthorizeType.PRIVATE : type;
			result.deniedRoles = deniedRoles.toArray(new String[deniedRoles
					.size()]);
			result.permittedRoles = allowedRoles
					.toArray(new String[allowedRoles.size()]);
			return result;
		}
	}

	@Override
	public void removeInstances(String[] names) {
	}

	@Override
	public void renameInstance(String oldName, String newName) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setFormPasswordSavedCount(int passwordDiffCount) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dispose() {

	}

}
