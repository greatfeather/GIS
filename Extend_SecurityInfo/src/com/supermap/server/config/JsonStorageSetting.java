package com.supermap.server.config;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class JsonStorageSetting extends CustomSecurityInfoStorageSetting {
    private static final long serialVersionUID = 1L;
    public String outputDirectory;
    public JsonStorageSetting() {
        super();
        this.type = SecurityInfoStorageType.CUSTOM;
    }

    public JsonStorageSetting(JsonStorageSetting jsonStorageSetting) {
        super(jsonStorageSetting);
        this.outputDirectory = jsonStorageSetting.outputDirectory;
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
        return new JsonStorageSetting(this);
    }

}
