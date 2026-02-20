async function fetchJenkinsCrumb(jenkinsUrl) {
  const crumbResponse = await fetch(`${jenkinsUrl}/crumbIssuer/api/json`);
  const crumbData = await crumbResponse.json();
  const {crumb, crumbRequestField} = crumbData;
  return {
    header: crumbRequestField,
    value: crumb,
  };
}

function getJenkinsCrumb(form) {
  const CRUMB_FIELD_NAME = 'Jenkins-Crumb';
  if (!form) return null;
  const crumbField = form.querySelector(`input[name="${CRUMB_FIELD_NAME}"]`);
  if (!crumbField) return null;
  return {
    header: CRUMB_FIELD_NAME,
    value: crumbField.value,
  };
}
