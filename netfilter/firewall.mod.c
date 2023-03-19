#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xdd8f8694, "module_layout" },
	{ 0x74309cc4, "nf_unregister_sockopt" },
	{ 0xecf8bb60, "nf_unregister_net_hook" },
	{ 0x22b15ff5, "nf_register_sockopt" },
	{ 0x813402d2, "nf_register_net_hook" },
	{ 0xaaa930a7, "init_net" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xc5850110, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D99D3C415910D69740F96E4");
