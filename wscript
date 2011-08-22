#!/usr/bin/env python
srcdir = "."
blddir = "build"
VERSION = "0.0.1"

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.tool_options("gcc")

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("gcc")  
  conf.check_tool("node_addon")

def build(bld):
  ### scryptc
  scryptc = bld.new_task_gen("cc")
  scryptc.source = "deps/crypto/crypto_scrypt-nosse.c"
  scryptc.includes = """
    deps/
    deps/crypto/
    deps/util/
  """
  scryptc.name = "scryptc"
  scryptc.target = "scryptc"
  scryptc.install_path = None
  scryptc.cflags = ["-fPIC"]
  
  sha256 = bld.new_task_gen("cc")
  sha256.source = "deps/crypto/sha256scrypt.c"
  sha256.includes = """
    deps/
    deps/crypto/
    deps/util/
  """
  sha256.name = "sha256"
  sha256.target = "sha256"
  sha256.install_path = None
  sha256.cflags = ["-fPIC"]
  
  obj = bld.new_task_gen('cxx', 'shlib', 'node_addon')
  obj.add_objects = "scryptc sha256"
  obj.includes = """
    deps
    deps/crypto/
  """  
  obj.name = "node-scrypt"
  obj.source = "scrypt.cc"
  obj.target = "scrypt"
  ### scryptc.install_path = None
  obj.cxxflags = ["-fPIC"]