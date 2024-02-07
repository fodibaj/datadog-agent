name 'datadog-agent-integrations-py3-dependencies'

dependency 'pip3'
dependency 'setuptools3'

if arm_target?
  # same with libffi to build the cffi wheel
  dependency 'libffi'
  # same with libxml2 and libxslt to build the lxml wheel
  dependency 'libxml2'
  dependency 'libxslt'
end

if not windows_target?
  dependency 'cyrus-sasl'
end

if linux_target?
  # odbc drivers used by the SQL Server integration
  dependency 'freetds'
  dependency 'msodbcsql18'
  # add nfsiostat script used by the nfsstat integration
  dependency 'nfsiostat'
  # gstatus binary used by the glusterfs integration
  dependency 'gstatus'
end
