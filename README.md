# Experimental x64 RE build configuration

This isolated branch contains only an AppVeyor configuration and its reviewed build inputs. It is not the game source branch, an official release, or an upstream endorsement.

The provider checks out this configuration commit normally, then runs `ci/run-client-build.ps1` from the install phase. The driver fetches the separately pinned public product source: b6205405c9976d8f1b659db919cb537e7d2dba08 plus exactly the three listed rendering-file replacements, composite tree 47eb9042c333f520ef7b555dca5d1727edff4c1b.

One manually selected Free standard Visual Studio 2022 x64 job is intended. Push, pull-request and scheduled builds must be disabled in the project settings. The driver also rejects non-manual and rerun jobs. There is no artifact glob, cache, deployment, automatic test discovery, SDK installation, or retry. The default branch is not changed.

The runtime contract is disabled unless explicitly enabled for the one manual build. Build success requires the pinned toolchain/UCRT, four targets, both mathematical golden checks, and three executed CTests. The resulting exact archive contains public-source RE outputs, notices and corresponding source; it contains no commercial game executable/assets, SDK library payload, PDB, private log or credential. Graphical correctness and original-game/replay/network parity remain unestablished.
