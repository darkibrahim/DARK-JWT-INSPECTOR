import unittest

from core import dependency_check, platform_detect


def detect(**kw):
    base = dict(env={}, os_release_text="", path_exists=lambda p: False, which=lambda c: None,
                system="Linux", machine="x86_64", release="6.1.0", py_version=(3, 11, 2))
    base.update(kw)
    return platform_detect.detect_platform(**base)


class PlatformTests(unittest.TestCase):
    def test_termux(self):
        i = detect(env={"PREFIX": "/data/data/com.termux/files/usr"}, machine="aarch64",
                   release="5.15.0-android13", which=lambda c: "/x" if c == "pkg" else None)
        self.assertTrue(i.is_termux)
        self.assertFalse(i.is_nethunter)
        self.assertEqual(i.package_manager, "pkg")
        self.assertEqual(i.arch_family, "ARM64 (aarch64)")
        self.assertNotIn("sudo apt", " ".join(platform_detect.install_hints(i)))

    def test_kali(self):
        i = detect(os_release_text='ID=kali\nPRETTY_NAME="Kali GNU/Linux Rolling"\n',
                   which=lambda c: "/x" if c == "apt" else None)
        self.assertTrue(i.is_kali)
        self.assertFalse(i.is_nethunter)
        self.assertEqual(i.environment, "Kali Linux")
        self.assertEqual(i.package_manager, "apt")

    def test_nethunter_rootless(self):
        i = detect(os_release_text="ID=kali\n", release="5.10.43-android12-9", machine="aarch64")
        self.assertTrue(i.is_nethunter)
        self.assertEqual(i.environment, "Kali NetHunter (rootless)")

    def test_arch(self):
        i = detect(os_release_text="ID=arch\n", which=lambda c: "/x" if c == "pacman" else None)
        self.assertTrue(i.is_arch)
        self.assertEqual(i.package_manager, "pacman")
        self.assertIn("pacman", " ".join(platform_detect.install_hints(i)))

    def test_old_python_and_odd_arch(self):
        i = detect(py_version=(3, 6, 9), machine="riscv64")
        self.assertFalse(i.python_ok)
        self.assertGreaterEqual(len(i.notes), 2)

    def test_os_release_parser(self):
        d = platform_detect.parse_os_release('# c\nID="arch"\nNAME=\'Arch\'\nbad line\n')
        self.assertEqual(d, {"ID": "arch", "NAME": "Arch"})

    def test_real_detection_runs(self):
        info = platform_detect.detect_platform()
        self.assertTrue(info.python_ok)
        self.assertTrue(info.to_dict()["architecture"])


class DependencyTests(unittest.TestCase):
    def test_check_and_matrix(self):
        deps = dependency_check.check_dependencies()
        self.assertTrue(deps[0].available)
        matrix = dependency_check.feature_matrix(deps)
        self.assertTrue(matrix["Offline decoding"]["available"])
        self.assertTrue(matrix["HS256/HS384/HS512 verification"]["available"])

    def test_matrix_without_cryptography(self):
        d = dependency_check.DependencyStatus("cryptography", False, False, "", "missing")
        m = dependency_check.feature_matrix([d])
        self.assertFalse(m["RS256/RS384/RS512 verification"]["available"])
        self.assertTrue(m["Offline decoding"]["available"])


if __name__ == "__main__":
    unittest.main()
