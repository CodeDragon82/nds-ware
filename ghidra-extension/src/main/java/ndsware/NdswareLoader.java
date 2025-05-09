/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ndsware;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStream.KaitaiStructError;
import ndsware.parsers.Nds;
import ndsware.parsers.Nds.CodeSection;
import ndsware.parsers.Nds.CodeSectionInfo;
import ndsware.parsers.Nds.Overlay;

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class NdswareLoader extends AbstractProgramWrapperLoader {

	private static final LanguageCompilerSpecPair LANGUAGE = new LanguageCompilerSpecPair("ARM:LE:32:v5t",
			"default");

	@Override
	public String getName() {

		return "Nintendo DS ROM (NDS)";
	}

	/**
	 * Parses the binary using the NDS Kaitai parser and returns the resulting data
	 * structure.
	 */
	private Nds loadNds(ByteProvider provider) throws KaitaiStructError, IOException {
		byte[] bytes = provider.readBytes(0, provider.length());
		ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
		KaitaiStream kaitaiStream = new ByteBufferKaitaiStream(byteBuffer);

		return new Nds(kaitaiStream);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			loadNds(provider);

			loadSpecs.add(new LoadSpec(this, 0, LANGUAGE, true));
		} catch (KaitaiStructError e) {
			// ignore
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		Memory memory = program.getMemory();
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		try {
			memory.createUninitializedBlock("Shared WRAM", addressSpace.getAddress(0x03000000), 0x8000, false);
			memory.createUninitializedBlock("I/O Ports", addressSpace.getAddress(0x04000000), 0x01000000, false);
			memory.createUninitializedBlock("Standard Palettes", addressSpace.getAddress(0x05000000), 0x800, false);
			memory.createUninitializedBlock("VRAM - Engine A, BG VRAM", addressSpace.getAddress(0x06000000), 0x80000,
					false);
			memory.createUninitializedBlock("VRAM - Engine B, BG VRAM", addressSpace.getAddress(0x06200000), 0x20000,
					false);
			memory.createUninitializedBlock("VRAM - Engine A, OBJ VRAM", addressSpace.getAddress(0x06400000), 0x40000,
					false);
			memory.createUninitializedBlock("VRAM - Engine B, OBJ VRAM", addressSpace.getAddress(0x06600000), 0x20000,
					false);
			memory.createUninitializedBlock("VRAM - \"LCDC\"-allocated", addressSpace.getAddress(0x06800000), 0xA4000,
					false);
			memory.createUninitializedBlock("OAM", addressSpace.getAddress(0x07000000), 0x800, false);
			memory.createUninitializedBlock("GBA Slot ROM", addressSpace.getAddress(0x08000000), 0x8000, false);
			memory.createUninitializedBlock("GBA Slot RAM", addressSpace.getAddress(0x0A000000), 0x10000, false);
			memory.createUninitializedBlock("BIOS", addressSpace.getAddress(0xFFFF0000), 0x8000, false);

		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException
				| AddressOutOfBoundsException e) {
			e.printStackTrace();
		}

		Nds nds = loadNds(provider);
		CodeSection arm9 = nds.arm9();
		CodeSectionInfo arm9Info = arm9.info();
		Address baseAddress = addressSpace.getAddress(arm9Info.loadAddress());
		InputStream data = new ByteArrayInputStream(arm9.data());

		try {
			memory.createInitializedBlock("Main Memory", baseAddress, data, 0x400000, monitor, false);
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException
				| IllegalArgumentException e) {
			e.printStackTrace();
		}

		long size;
		for (Overlay overlay : nds.arm9Overlays()) {
			baseAddress = addressSpace.getAddress(overlay.info().baseAddress());
			size = overlay.info().length();
			data = new ByteArrayInputStream(overlay.file().data());

			try {
				memory.createInitializedBlock("Overlay" + overlay.info().index(), baseAddress, data, size, monitor,
						true);
			} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException
					| IllegalArgumentException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
