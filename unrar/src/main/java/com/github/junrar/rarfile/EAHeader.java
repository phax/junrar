/*
 * Copyright (c) 2007 innoSysTec (R) GmbH, Germany. All rights reserved.
 * Original author: Edmund Wagner
 * Creation date: 27.11.2007
 *
 * Source: $HeadURL$
 * Last changed: $LastChangedDate$
 *
 *
 * the unrar licence applies to all junrar source and binary distributions
 * you are not allowed to use this source to re-create the RAR compression algorithm
 *
 * Here some html entities which can be used for escaping javadoc tags:
 * "&":  "&#038;" or "&amp;"
 * "<":  "&#060;" or "&lt;"
 * ">":  "&#062;" or "&gt;"
 * "@":  "&#064;"
 */
package com.github.junrar.rarfile;

import com.github.junrar.io.Raw;


/**
 * extended archive CRC header
 *
 */
public class EAHeader
extends SubBlockHeader
{
	public static final short EAHeaderSize = 10;

	private final int unpSize;
	private final byte unpVer;
	private final byte method;
	private final int EACRC;

	public EAHeader(final SubBlockHeader sb, final byte[] eahead)
	{
		super(sb);
		int pos = 0;
		unpSize = Raw.readIntLittleEndian(eahead, pos);
		pos+=4;
		unpVer = (byte) (eahead[pos]&0xff);
		pos++;
		method = (byte) (eahead[pos]&0xff);
		pos++;
		EACRC = Raw.readIntLittleEndian(eahead, pos);
	}

	/**
	 * @return the eACRC
	 */
	public int getEACRC() {
		return EACRC;
	}

	/**
	 * @return the method
	 */
	public byte getMethod() {
		return method;
	}

	/**
	 * @return the unpSize
	 */
	public int getUnpSize() {
		return unpSize;
	}

	/**
	 * @return the unpVer
	 */
	public byte getUnpVer() {
		return unpVer;
	}

	@Override
  public void print()
	{
		super.print();
		logger.info("unpSize: "+unpSize);
		logger.info("unpVersion: " + unpVer);
		logger.info("method: "+method);
		logger.info("EACRC:" + EACRC);
	}
}

