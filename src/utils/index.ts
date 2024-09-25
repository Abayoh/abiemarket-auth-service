/**
 * Takes a number in seconds and returns the date in the future.
 * Optionally takes a second date parameter. In that case
 * the date in the future will be calculated from that date instead of now.
 * @param time the time in seconds
 * @param date the date to calculate from
 * @returns the date in the future
 */
export function fromDate(time: number, date = Date.now()) {
  return new Date(date + time * 1000);
}

/**
 * Get the current date
 * @returns the current date
 */
export function now() {
  return new Date();
}

/**
 * Checks if a date has expired
 * if a number is passed it will be treated as a date in seconds
 * @param date the date to check
 * @returns true if the date has expired
 */
export function hasExpired(date: Date | number) {
  if (typeof date === "number") {
    return date < nowInSeconds();
  }
  return date < now();
}

/**
 * Get the current date in miliseconds
 * @returns the current date in miliseconds
 *
 */
export function nowInMiliseconds() {
  return Date.now();
}

/**
 * Get the current date in seconds
 * @returns the current date in seconds
 * */
export function nowInSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function toPascalCase(str: string = "") {
  return (
    str
      ?.match(/[a-z]+/gi)
      ?.map(function (word: string) {
        // Capitalize the first letter and make the rest lowercase
        return word.charAt(0).toUpperCase() + word.substr(1).toLowerCase();
      })
      .join("") || "ErrorName"
  );
}

export function arraysAreDifferent(arr1: string[], arr2: string[]) {
  // Check if the arrays have different lengths
  if (arr1.length !== arr2.length) {
    return true;
  }

  // Check if any elements in the arrays are different
  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return true;
    }
  }

  // If no differences are found, return false (arrays are the same)
  return false;
}
