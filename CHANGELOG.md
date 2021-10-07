# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [Unreleased]


## [0.3.1] — 2021-10-07
### Fixed
 - Use correct version in `parsuricata.__version__`

### Changed
 - Improve performance of `Setting` class instantiation


## [0.3.0] — 2021-10-07
### Added
 - _DOC:_ added CHANGELOG

### Fixed
 - Allow comments in rules files (e.g. `# Comment`)
 - Allow any string for protocol (previously, a static list of protocols was used, but this list changes all the time)
 - Allow numbers in option keywords (e.g. `asn1: double_overflow;`)
 - Allow dashes in option keywords (e.g. `app-layer-event:applayer_mismatch_protocol_both_directions;`)
 - Allow comma-delimited literals in option settings (e.g. `flowint:applayer.anomaly.count,+,1;`)
 - Allow unescaped double quotes inside quoted strings, like Suricata allows (e.g. `pcre:"/^["']?post/Ri";`)
 - Faithfully reproduce quoted strings and unquoted literals in option settings

### Changed
 - Changed minimum Python version to 3.6
 - Upgraded lark-parser to 0.12.0
 - _DEV:_ upgraded pytest to 6.2.5


## [0.2.4] — 2021-09-28
### Fixed
 - Allow option names with periods (e.g. `tls.cert_subject;`). Thanks, [@jgrunzweig](https://github.com/jgrunzweig). [GH#10](https://github.com/theY4Kman/parsuricata/issues/10)
 - Properly stringify port groupings. Thanks, [@jgrunzweig](https://github.com/jgrunzweig). [GH#8](https://github.com/theY4Kman/parsuricata/issues/8)
 - Allow ungrouped port ranges (e.g. `alert ip any 80:` or `alert ip any :100`). Thanks, [@jgrunzweig](https://github.com/jgrunzweig). [GH#9](https://github.com/theY4Kman/parsuricata/issues/9)


## [0.2.3] — 2021-05-08
### Fixed
 - Allow escape sequences in strings. [GH#3](https://github.com/theY4Kman/parsuricata/issues/3)


## [0.2.2] — 2021-05-08
### Fixed
 - Allow escaped newline before a rule's first option. [GH#4](https://github.com/theY4Kman/parsuricata/issues/4)
 - Allow trailing newlines before EOF


## [0.2.1] — 2021-05-07
### Added
 - Added support for negated settings (e.g. `content: !"stuff";`). [GH#5](https://github.com/theY4Kman/parsuricata/issues/5), [GH#1](https://github.com/theY4Kman/parsuricata/issues/1)


## [0.1.1] — 2019-05-14
### Added
 - _DOC:_ add usage example to README


## [0.1.0] — 2019-05-14
### Added
 - Basic Suricata rules parser
 - Basic rules beautification
