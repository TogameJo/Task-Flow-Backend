package com.example.demo_authen_jwt.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class DateUtils {
  private static final DateTimeFormatter YYYY_MM_DD_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
  private static final DateTimeFormatter YYYY_MM_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM");
  private static final DateTimeFormatter MM_DD_YYYY_HH_MM_SS_FORMAT = DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss");
  private static final String TIMEZONE_UTC7 = "Asia/Ho_Chi_Minh";


  public static String getCurrentDateString() {
    return LocalDate.now().toString();
  }

  public static long convertToTimestamp(String dateTimeStr) throws ParseException {
    SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss");

    Date date = sdf.parse(dateTimeStr);

    return date.getTime();
  }

  public static String convertToMillisSecond(Long time) {
    try {
      Date date = new Date(time);
      SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
      return sdf.format(date);
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static long convertToMillisSecond(String dateTime) {
    try {
      LocalDate localDate = LocalDate.parse(dateTime, YYYY_MM_DD_FORMAT);
      return localDate.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static long getMillisSecond() {
    return Calendar.getInstance().getTimeInMillis();
  }

  public static Long getStartOfDayInTimestamp(String dateFrom) {
    if (dateFrom == null) return null;
    try {
      LocalDate date = LocalDate.parse(dateFrom, YYYY_MM_DD_FORMAT);
      LocalDateTime endOfDay = date.atTime(0, 0, 0);
      return endOfDay.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    } catch (DateTimeParseException e) {
      return null;
    }
  }

  public static Long getEndOfDayInTimestamp(String dateTo) {
    if (dateTo == null) return null;
    try {
      LocalDate date = LocalDate.parse(dateTo, YYYY_MM_DD_FORMAT);
      LocalDateTime endOfDay = date.atTime(23, 59, 59);
      return endOfDay.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    } catch (DateTimeParseException e) {
      return null;
    }
  }

  public static String convertTimestampToDateTime(long timestampMillis) {
    LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(timestampMillis), ZoneId.systemDefault());
    return MM_DD_YYYY_HH_MM_SS_FORMAT.format(dateTime);
  }

  public static String convertTimestampToDateTime(LocalDateTime dateTime) {
    return MM_DD_YYYY_HH_MM_SS_FORMAT.format(dateTime);
  }

  public static String getStartTimeOfDayInString() {
    LocalDate currentDate = LocalDate.now();
    LocalTime startTime = LocalTime.MIN;
    LocalDateTime startOfDay = LocalDateTime.of(currentDate, startTime);

    return startOfDay.format(MM_DD_YYYY_HH_MM_SS_FORMAT);
  }

  public static String getStartTimeOfDayInString(int year, int month, int day) {
    LocalDate date = LocalDate.of(year, month, day);
    LocalTime startTime = LocalTime.MIN;
    LocalDateTime startOfDay = LocalDateTime.of(date, startTime);

    return startOfDay.format(MM_DD_YYYY_HH_MM_SS_FORMAT);
  }

  public static String getSpecificTimeOfDayInString(int year, int month, int day, int hour) {
    LocalDate date = LocalDate.of(year, month, day);
    LocalTime time = LocalTime.of(hour, 0, 0);
    LocalDateTime specificTimeOfDay = LocalDateTime.of(date, time);

    return specificTimeOfDay.format(MM_DD_YYYY_HH_MM_SS_FORMAT);
  }

  public static String getEndTimeOfDayInString() {
    LocalDate currentDate = LocalDate.now();
    LocalTime endTime = LocalTime.MAX;
    LocalDateTime endOfDay = LocalDateTime.of(currentDate, endTime);

    return endOfDay.format(MM_DD_YYYY_HH_MM_SS_FORMAT);
  }

  public static long calculateDateDifference(String fromDateStr, String toDateStr) {
    try {
      LocalDate fromDate = LocalDate.parse(fromDateStr, YYYY_MM_DD_FORMAT);
      LocalDate toDate = LocalDate.parse(toDateStr, YYYY_MM_DD_FORMAT);
      // Using ChronoUnit.DAYS.between to calculate the difference in days
      long daysBetween = ChronoUnit.DAYS.between(fromDate, toDate);
      return daysBetween + 1; // to be inclusive of the end date
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static String calculatePreviousDate(String initialDateStr, long daysBefore) {
    try {
      LocalDate initialDate = LocalDate.parse(initialDateStr, YYYY_MM_DD_FORMAT);
      LocalDate previousDate = initialDate.minusDays(daysBefore);
      return previousDate.format(YYYY_MM_DD_FORMAT);
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static Map<String, Integer> getCalendarDayMap(Long startDate, Long endDate) {
    Map<String, Integer> dateMap = new TreeMap<>();
    ZoneId zone = ZoneId.systemDefault();

    LocalDate start = Instant.ofEpochMilli(startDate).atZone(zone).toLocalDate();
    LocalDate end = Instant.ofEpochMilli(endDate).atZone(zone).toLocalDate();

    while (!start.isAfter(end)) {
      String formattedDate = start.format(YYYY_MM_DD_FORMAT);
      dateMap.put(formattedDate, 0);
      start = start.plusDays(1);
    }

    return dateMap;
  }

  public static Map<String, Integer> getCalendarMonthMap(Long startDate, Long endDate) {
    Map<String, Integer> dateMap = new TreeMap<>();

    LocalDate start = Instant.ofEpochMilli(startDate).atZone(ZoneId.systemDefault()).toLocalDate();
    LocalDate end = Instant.ofEpochMilli(endDate).atZone(ZoneId.systemDefault()).toLocalDate();

    while (!start.isAfter(end)) {
      String formattedDate = start.format(YYYY_MM_FORMAT);
      dateMap.put(formattedDate, 0);
      start = start.plusMonths(1);
    }

    return dateMap;
  }

  public static long convertLocalDateTimeToMillis(LocalDateTime localDateTime) {
    return localDateTime.atZone(ZoneId.of(TIMEZONE_UTC7)).toInstant().toEpochMilli();
  }

  public static LocalDateTime createDateFromMillisV2(long millis) {
    Instant instant = Instant.ofEpochMilli(millis);
    ZoneId zoneId = ZoneId.of(TIMEZONE_UTC7);
    ZonedDateTime zonedDateTime = instant.atZone(zoneId);
    return zonedDateTime.toLocalDateTime();
  }

  public static String convertIsoToCustomFormat(String isoDateString) {
    SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    isoFormat.setTimeZone(TimeZone.getTimeZone("UTC")); // Set timezone to UTC for parsing

    SimpleDateFormat customFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
    customFormat.setTimeZone(TimeZone.getTimeZone("GMT+7")); // Set timezone to default for formatting

    try {
      Date date = isoFormat.parse(isoDateString);
      return customFormat.format(date);
    } catch (ParseException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static long convertMilliSecondsToSeconds(long milliseconds) {
    return milliseconds / 1000;
  }

  public static String convertTimestampToDateString_yyyyMMdd(long timestamp) {
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    Date date = new Date(timestamp);

    return sdf.format(date);
  }

  public static String convertDateFormat(String inputDate) {
    DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("MM/dd/yyyy");
    LocalDate date = LocalDate.parse(inputDate, inputFormatter);
    return date.format(outputFormatter);
  }

  public static String formatTimestamp(long timestamp) {
    LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), ZoneId.systemDefault());

    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy H'h'mm");

    return dateTime.format(formatter);
  }
}
