FROM tomcat:10.1.40-jdk17

#ARG ARTIFACT_ID
#ENV ARTIFACT_ID ${ARTIFACT_ID}

#ARG ENVIRONMENT
#RUN echo ${ENVIRONMENT}

#New Code
ENV CATALINA_OPTS="-server -Xmx2G -Xms1G -XX:+UseG1GC -XX:MaxGCPauseMillis=20 -XX:InitiatingHeapOccupancyPercent=35 -XX:+DisableExplicitGC -Djava.awt.headless=true"
ENV api_context-path="/hcp-auth-webapp"
ADD target/device-activation.war /tmp/hcp-auth-webapp.war
COPY src/scripts/* /opt/hcp-auth-webapp/bin/

# Add conf directory
ADD config/dev/ /usr/local/tomcat/conf/hcp-auth-webapp/

# Add context file
ADD config/dev/context.xml /usr/local/tomcat/conf/Catalina/localhost/hcp-auth-webapp.xml

#Add server.xml
ADD config/dev/server.xml /usr/local/tomcat/conf/server.xml
 
RUN chmod 755 /opt/hcp-auth-webapp/bin/start.sh
 
RUN rm -rf /usr/local/tomcat/webapps/* && \
    mv /tmp/hcp-auth-webapp.war /usr/local/tomcat/webapps/
RUN addgroup --system appgroup 
RUN adduser --system appuser --ingroup appgroup
RUN chown -R appuser:appgroup /usr/local/tomcat/
USER appuser  
ENTRYPOINT /bin/sh /opt/hcp-auth-webapp/bin/start.sh