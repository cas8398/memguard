import 'package:flutter/foundation.dart';
import 'package:flutter_fastlog/flutter_fastlog.dart';

void logger() {
  FastLog.config(
    showLog: !kReleaseMode,
    isColored: false,
    useEmoji: false,
    outputStyle: OutputStyle.none,
    prettyJson: false,
    messageLimit: 300,
    showTime: false,
    showCaller: false,
    logLevel: "TRACE", // Options: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
  );
}
