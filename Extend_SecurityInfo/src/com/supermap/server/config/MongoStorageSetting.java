package com.supermap.server.config;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class MongoStorageSetting extends CustomSecurityInfoStorageSetting {
	private static final long serialVersionUID = 8989015698152942168L;
    public String outputDirectory;
    public MongoStorageSetting(){
    	this.type = SecurityInfoStorageType.CUSTOM;
    }
    public MongoStorageSetting(MongoStorageSetting mongoStorageSetting){
    	super(mongoStorageSetting);
    	this.type = SecurityInfoStorageType.CUSTOM;
    	this.outputDirectory = mongoStorageSetting.outputDirectory;
    }
    @Override
    public boolean equals(Object objToEqual) {
    	if (objToEqual == null) {
            return false;
        }
        if (!(objToEqual instanceof JsonStorageSetting)) {
            return false;
        }
        JsonStorageSetting obj = (JsonStorageSetting) objToEqual;
        EqualsBuilder builder = new EqualsBuilder();
        builder.append(this.outputDirectory, obj.outputDirectory);
        return builder.isEquals();
    }

    @Override
    public int hashCode() {
    	HashCodeBuilder builder = new HashCodeBuilder().appendSuper(super.hashCode()).append(this.outputDirectory);
        return builder.toHashCode();
    }

    @Override
    public SecurityInfoStorageSetting copy() {
        return new MongoStorageSetting(this);
    }

}
