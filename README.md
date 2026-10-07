# FlySafe IGC validator

Verifies XFS IGC recordings from FlySafe Android, iOS and the physical vario using the public Ed25519 key compiled into `public_key.h`.

## Usage

```bat
vali-flysafe.exe "C:\Flights\flight.igc"
```

On Linux:

```sh
./vali-flysafe flight.igc
```

Exit codes: **0** valid, **1** invalid, **2** invocation or initialization error.
The Windows x64 executable statically links libsodium and requires no separate DLL.

## Validation

- The first record must begin with `AXFS`. A serial number is optional and is not validated.
- Required recorder metadata, date and altitude headers must be present.
- B-record coordinates, altitude fields, UTC order and declared FXA extensions are checked.
- The file must declare `LXFSFLYSAFE ED25519-SHA256-V1`. Verification uses the public key compiled into the validator.
- Legacy `LXFSKEY:` lines are accepted as signed comments; their values are ignored for key selection.
- The signature must be two G records containing 64 hex characters each.
- Original CRLF line endings must be preserved.

The signature is plain Ed25519 over the 32-byte SHA-256 digest of protected IGC records. Observer headers (`HO`) and comments from manufacturers other than XFS are excluded. Protected records appended after the signature are rejected.

## Recorded altitude

Android and native iOS write absolute ISA pressure altitude in metres into the first B-record altitude field when a fresh device pressure reading is available. Unavailable or stale pressure readings are written as `00000`. The second altitude field contains GNSS altitude above mean sea level, declared by `HFALGALTGPS:GEO`.

Pressure altitude uses the standard 1013.25 hPa reference. Android pressure readings are in hPa; Core Motion readings are in kPa. Recorded pressure altitude is independent of GPS altitude, relative altitude, vario filtering and sound settings. Mobile pressure samples expire after three seconds and must be within three seconds of the recorded fix. `HFALPALTPRESSURE` declares `ISA` on devices with a pressure sensor and `NIL` otherwise. On iOS, pressure readings require motion permission.

Android converts WGS84 ellipsoid altitude using AndroidX's geoid model. iOS uses Core Location's sea-level altitude. The physical vario records NMEA GGA mean-sea-level altitude and ISA pressure altitude from its barometer.

During GNSS loss, pressure recording continues using elapsed time anchored to GNSS UTC and the last recorded coordinates. These fixes are marked `V` with zero GNSS altitude. Mobile fix accuracy fields are declared by `I013638FXA`.

## Build

Linux requires GCC and libsodium development files:

```sh
make
```

Windows requires MinGW x64 and the libsodium archive specified in `dependency.json`. Extract its headers and static library under `vendor/libsodium-win64/`, then run:

```sh
make windows
```

`build-manifest.json` contains hashes of the supplied binaries and synthetic sample files. `LICENSE.libsodium.txt` contains the dependency licence.
