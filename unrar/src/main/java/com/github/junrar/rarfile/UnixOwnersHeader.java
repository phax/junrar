package com.github.junrar.rarfile;

import com.github.junrar.io.Raw;


public class UnixOwnersHeader
extends SubBlockHeader
{
	private int ownerNameSize;
	private int groupNameSize;
	private String owner;
	private String group;

	public  UnixOwnersHeader(final SubBlockHeader sb, final byte[] uoHeader) {
		super(sb);
		int pos = 0;
		ownerNameSize = Raw.readShortLittleEndian(uoHeader, pos)&0xFFFF;
		pos+=2;
		groupNameSize = Raw.readShortLittleEndian(uoHeader, pos)&0xFFFF;
		pos+=2;
		if(pos+ownerNameSize<uoHeader.length){
			final byte[] ownerBuffer = new byte[ownerNameSize];
			System.arraycopy(uoHeader, pos, ownerBuffer, 0, ownerNameSize);
			owner = new String(ownerBuffer);
		}
		pos+=ownerNameSize;
		if(pos+groupNameSize<uoHeader.length){
			final byte[] groupBuffer = new byte[groupNameSize];
			System.arraycopy(uoHeader, pos, groupBuffer, 0, groupNameSize);
			group = new String(groupBuffer);
		}
	}
	/**
	 * @return the group
	 */
	public String getGroup() {
		return group;
	}
	/**
	 * @param group the group to set
	 */
	public void setGroup(final String group) {
		this.group = group;
	}
	/**
	 * @return the groupNameSize
	 */
	public int getGroupNameSize() {
		return groupNameSize;
	}
	/**
	 * @param groupNameSize the groupNameSize to set
	 */
	public void setGroupNameSize(final int groupNameSize) {
		this.groupNameSize = groupNameSize;
	}
	/**
	 * @return the owner
	 */
	public String getOwner() {
		return owner;
	}
	/**
	 * @param owner the owner to set
	 */
	public void setOwner(final String owner) {
		this.owner = owner;
	}
	/**
	 * @return the ownerNameSize
	 */
	public int getOwnerNameSize() {
		return ownerNameSize;
	}
	/**
	 * @param ownerNameSize the ownerNameSize to set
	 */
	public void setOwnerNameSize(final int ownerNameSize) {
		this.ownerNameSize = ownerNameSize;
	}

	/* (non-Javadoc)
	 * @see de.innosystec.unrar.rarfile.SubBlockHeader#print()
	 */
	@Override
  public void print(){
		super.print();
		logger.info("ownerNameSize: "+ownerNameSize);
		logger.info("owner: "+owner);
		logger.info("groupNameSize: "+groupNameSize);
		logger.info("group: "+group);
	}
}
